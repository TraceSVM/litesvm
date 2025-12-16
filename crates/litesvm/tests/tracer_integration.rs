//! Integration tests for the semantic tracer feature.
//!
//! These tests verify that the tracer correctly captures execution traces
//! when running BPF programs through LiteSVM.

#![cfg(feature = "semantic-tracer")]

use {
    litesvm::LiteSVM,
    solana_account::Account,
    solana_instruction::{account_meta::AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_message::Message,
    solana_pubkey::{pubkey, Pubkey},
    solana_signer::Signer,
    solana_transaction::Transaction,
    std::path::PathBuf,
};

fn read_counter_program() -> Vec<u8> {
    let mut so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    so_path.push("test_programs/target/deploy/counter.so");
    std::fs::read(so_path).unwrap()
}

fn make_counter_tx(
    program_id: Pubkey,
    counter_address: Pubkey,
    payer_pk: &Pubkey,
    blockhash: solana_hash::Hash,
    payer_kp: &Keypair,
    deduper: u8,
) -> Transaction {
    let msg = Message::new_with_blockhash(
        &[Instruction {
            program_id,
            accounts: vec![AccountMeta::new(counter_address, false)],
            data: vec![0, deduper],
        }],
        Some(payer_pk),
        &blockhash,
    );
    Transaction::new(&[payer_kp], msg, blockhash)
}

#[test]
fn test_traced_execution_basic() {
    let mut svm = LiteSVM::new();
    let payer_kp = Keypair::new();
    let payer_pk = payer_kp.pubkey();
    let program_id = pubkey!("GtdambwDgHWrDJdVPBkEHGhCwokqgAoch162teUjJse2");

    svm.add_program(program_id, &read_counter_program())
        .unwrap();
    svm.airdrop(&payer_pk, 1000000000).unwrap();

    let blockhash = svm.latest_blockhash();
    let counter_address = pubkey!("J39wvrFY2AkoAUCke5347RMNk3ditxZfVidoZ7U6Fguf");

    svm.set_account(
        counter_address,
        Account {
            lamports: 5,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        },
    )
    .unwrap();

    let tx = make_counter_tx(
        program_id,
        counter_address,
        &payer_pk,
        blockhash,
        &payer_kp,
        0,
    );

    // Execute with tracing enabled (cfg=true, dataflow=true)
    let (tx_result, traces) = svm.send_transaction_traced(tx, true, true);

    // Verify transaction succeeded
    assert!(tx_result.is_ok(), "Transaction should succeed");

    // Verify we got traces
    assert!(!traces.is_empty(), "Should have at least one trace");

    // Verify the trace contains execution events
    let trace = &traces[0];
    assert!(
        !trace.execution_tree.is_empty(),
        "Trace should have execution events"
    );

    // Verify counter was incremented
    assert_eq!(
        svm.get_account(&counter_address).unwrap().data,
        1u32.to_le_bytes().to_vec()
    );
}

#[test]
fn test_traced_execution_with_cfg() {
    let mut svm = LiteSVM::new();
    let payer_kp = Keypair::new();
    let payer_pk = payer_kp.pubkey();
    let program_id = pubkey!("GtdambwDgHWrDJdVPBkEHGhCwokqgAoch162teUjJse2");

    svm.add_program(program_id, &read_counter_program())
        .unwrap();
    svm.airdrop(&payer_pk, 1000000000).unwrap();

    let blockhash = svm.latest_blockhash();
    let counter_address = pubkey!("J39wvrFY2AkoAUCke5347RMNk3ditxZfVidoZ7U6Fguf");

    svm.set_account(
        counter_address,
        Account {
            lamports: 5,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        },
    )
    .unwrap();

    let tx = make_counter_tx(
        program_id,
        counter_address,
        &payer_pk,
        blockhash,
        &payer_kp,
        0,
    );

    // Execute with CFG analysis enabled
    let (tx_result, traces) = svm.send_transaction_traced(tx, true, false);

    assert!(tx_result.is_ok(), "Transaction should succeed");
    assert!(!traces.is_empty(), "Should have traces");

    let trace = &traces[0];

    // CFG should be available
    assert!(
        trace.control_flow_graph.is_some(),
        "CFG should be generated when enable_cfg=true"
    );

    let cfg = trace.control_flow_graph.as_ref().unwrap();
    assert!(
        !cfg.basic_blocks.is_empty(),
        "CFG should have basic blocks"
    );
}

#[test]
fn test_traced_execution_with_dataflow() {
    let mut svm = LiteSVM::new();
    let payer_kp = Keypair::new();
    let payer_pk = payer_kp.pubkey();
    let program_id = pubkey!("GtdambwDgHWrDJdVPBkEHGhCwokqgAoch162teUjJse2");

    svm.add_program(program_id, &read_counter_program())
        .unwrap();
    svm.airdrop(&payer_pk, 1000000000).unwrap();

    let blockhash = svm.latest_blockhash();
    let counter_address = pubkey!("J39wvrFY2AkoAUCke5347RMNk3ditxZfVidoZ7U6Fguf");

    svm.set_account(
        counter_address,
        Account {
            lamports: 5,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        },
    )
    .unwrap();

    let tx = make_counter_tx(
        program_id,
        counter_address,
        &payer_pk,
        blockhash,
        &payer_kp,
        0,
    );

    // Execute with dataflow analysis enabled
    let (tx_result, traces) = svm.send_transaction_traced(tx, false, true);

    assert!(tx_result.is_ok(), "Transaction should succeed");
    assert!(!traces.is_empty(), "Should have traces");

    let trace = &traces[0];

    // Dataflow should be available
    assert!(
        trace.dataflow.is_some(),
        "Dataflow state should be present when enable_dataflow=true"
    );
}

#[test]
fn test_traced_execution_multiple_transactions() {
    let mut svm = LiteSVM::new();
    let payer_kp = Keypair::new();
    let payer_pk = payer_kp.pubkey();
    let program_id = pubkey!("GtdambwDgHWrDJdVPBkEHGhCwokqgAoch162teUjJse2");

    svm.add_program(program_id, &read_counter_program())
        .unwrap();
    svm.airdrop(&payer_pk, 1000000000).unwrap();

    let blockhash = svm.latest_blockhash();
    let counter_address = pubkey!("J39wvrFY2AkoAUCke5347RMNk3ditxZfVidoZ7U6Fguf");

    svm.set_account(
        counter_address,
        Account {
            lamports: 5,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        },
    )
    .unwrap();

    // Execute multiple transactions with tracing
    for i in 0..3 {
        let tx = make_counter_tx(
            program_id,
            counter_address,
            &payer_pk,
            blockhash,
            &payer_kp,
            i,
        );

        let (tx_result, traces) = svm.send_transaction_traced(tx, true, true);
        assert!(tx_result.is_ok(), "Transaction {} should succeed", i);
        assert!(!traces.is_empty(), "Transaction {} should have traces", i);
    }

    // Verify counter was incremented 3 times
    assert_eq!(
        svm.get_account(&counter_address).unwrap().data,
        3u32.to_le_bytes().to_vec()
    );
}

#[test]
fn test_traced_execution_inspect_events() {
    let mut svm = LiteSVM::new();
    let payer_kp = Keypair::new();
    let payer_pk = payer_kp.pubkey();
    let program_id = pubkey!("GtdambwDgHWrDJdVPBkEHGhCwokqgAoch162teUjJse2");

    svm.add_program(program_id, &read_counter_program())
        .unwrap();
    svm.airdrop(&payer_pk, 1000000000).unwrap();

    let blockhash = svm.latest_blockhash();
    let counter_address = pubkey!("J39wvrFY2AkoAUCke5347RMNk3ditxZfVidoZ7U6Fguf");

    svm.set_account(
        counter_address,
        Account {
            lamports: 5,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        },
    )
    .unwrap();

    let tx = make_counter_tx(
        program_id,
        counter_address,
        &payer_pk,
        blockhash,
        &payer_kp,
        0,
    );

    let (tx_result, traces) = svm.send_transaction_traced(tx, true, true);
    assert!(tx_result.is_ok());

    let trace = &traces[0];

    // Count different event types in call frames
    let mut instruction_count = 0;
    let mut syscall_count = 0;

    fn count_events(frame: &litesvm::tracer::TracedCallFrame, insn_count: &mut usize, syscall_count: &mut usize) {
        for event in &frame.events {
            match event {
                litesvm::tracer::TraceEvent::Instruction(_) => *insn_count += 1,
                litesvm::tracer::TraceEvent::Syscall(_) => *syscall_count += 1,
                _ => {}
            }
        }
        for sub in &frame.sub_calls {
            count_events(sub, insn_count, syscall_count);
        }
    }

    for frame in &trace.execution_tree {
        count_events(frame, &mut instruction_count, &mut syscall_count);
    }

    // The counter program should execute some instructions
    assert!(
        instruction_count > 0,
        "Should have recorded instruction events"
    );

    println!("Traced {} instructions and {} syscalls", instruction_count, syscall_count);
}
