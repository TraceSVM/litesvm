//! Example: Trace a Solana program execution with semantic tracer
//!
//! This example demonstrates how to use LiteSVM's semantic tracer to capture
//! detailed execution traces including CFG analysis and dataflow tracking.
//!
//! Run with:
//!   cargo run --example trace_program --features semantic-tracer

use litesvm::LiteSVM;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::fs;
use std::path::PathBuf;

fn read_counter_program() -> Vec<u8> {
    let mut so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    so_path.push("test_programs/target/deploy/counter.so");
    fs::read(&so_path).unwrap_or_else(|_| {
        panic!(
            "Could not read counter.so at {:?}. Run 'cargo build-sbf' in test_programs/ first.",
            so_path
        )
    })
}

fn main() {
    println!("=== LiteSVM Semantic Tracer Example ===\n");

    // Set up LiteSVM
    let mut svm = LiteSVM::new();
    let payer_kp = Keypair::new();
    let payer_pk = payer_kp.pubkey();
    let program_id = pubkey!("GtdambwDgHWrDJdVPBkEHGhCwokqgAoch162teUjJse2");

    // Load the counter program
    println!("Loading counter program...");
    svm.add_program(program_id, &read_counter_program())
        .expect("Failed to add program");

    // Fund the payer
    svm.airdrop(&payer_pk, 1_000_000_000).unwrap();

    let blockhash = svm.latest_blockhash();
    let counter_address = pubkey!("J39wvrFY2AkoAUCke5347RMNk3ditxZfVidoZ7U6Fguf");

    // Set up the counter account with initial value 0
    svm.set_account(
        counter_address,
        Account {
            lamports: 1_000_000,
            data: vec![0_u8; std::mem::size_of::<u32>()],
            owner: program_id,
            ..Default::default()
        },
    )
    .unwrap();

    println!("Initial counter value: 0");
    println!("Program ID: {}", program_id);
    println!("Counter address: {}\n", counter_address);

    // Create transaction to increment the counter
    let tx = Transaction::new(
        &[&payer_kp],
        Message::new_with_blockhash(
            &[Instruction {
                program_id,
                accounts: vec![AccountMeta::new(counter_address, false)],
                data: vec![0, 0], // instruction 0 = increment
            }],
            Some(&payer_pk),
            &blockhash,
        ),
        blockhash,
    );

    println!("Executing transaction with tracing enabled...\n");

    // Execute with tracing enabled
    #[cfg(feature = "semantic-tracer")]
    {
        let (tx_result, traces) = svm.send_transaction_traced(tx, true, true);

        match &tx_result {
            Ok(meta) => {
                println!("Transaction SUCCESS");
                println!("  Compute units: {}", meta.compute_units_consumed);
                println!("  Logs:");
                for log in &meta.logs {
                    println!("    {}", log);
                }
            }
            Err(failed) => {
                println!("Transaction FAILED: {:?}", failed.err);
                println!("  Logs:");
                for log in &failed.meta.logs {
                    println!("    {}", log);
                }
            }
        }

        // Verify counter was incremented
        let counter_data = svm.get_account(&counter_address).unwrap().data;
        let counter_value = u32::from_le_bytes(counter_data.try_into().unwrap());
        println!("\nCounter value after execution: {}", counter_value);

        println!("\n=== Trace Analysis ===\n");

        if traces.is_empty() {
            println!("No traces captured (program may not be a BPF program)");
        } else {
            for (i, trace) in traces.iter().enumerate() {
                println!("--- Trace {} ---", i);
                println!("Program ID: {:?}", trace.program_id);
                println!("Total compute units: {}", trace.total_compute_units);
                println!("Result: {:?}", trace.result);
                println!("Execution frames: {}", trace.execution_tree.len());

                // Print execution tree summary
                print_execution_summary(&trace.execution_tree, 0);

                // CFG analysis
                if let Some(cfg) = &trace.control_flow_graph {
                    println!("\n  CFG Analysis:");
                    println!("    Basic blocks: {}", cfg.basic_blocks.len());
                    println!("    Edges: {}", cfg.edges.len());
                    if !cfg.loops.is_empty() {
                        println!("    Detected loops: {}", cfg.loops.len());
                        for (j, loop_info) in cfg.loops.iter().enumerate() {
                            println!("      Loop {}: header at PC {}", j, loop_info.header_pc);
                        }
                    }
                }

                // Dataflow analysis
                if let Some(dataflow) = &trace.dataflow {
                    println!("\n  Dataflow Analysis:");
                    println!("    Value definitions tracked: {}", dataflow.definitions.len());
                    println!("    Value uses tracked: {}", dataflow.uses.len());
                    println!("    Memory stores: {}", dataflow.memory_stores.len());

                    // Show tainted values if any
                    let tainted_count = dataflow
                        .definitions
                        .values()
                        .filter(|d| !d.taint.is_empty())
                        .count();
                    if tainted_count > 0 {
                        println!("    Tainted values: {}", tainted_count);
                    }
                }

                println!();
            }

            // Convert to queryable format
            println!("\n=== Generating Queryable Trace ===\n");

            for (i, trace) in traces.iter().enumerate() {
                // Full queryable trace (with all instructions)
                let queryable_full = litesvm::tracer::QueryableTrace::from_trace_context(trace);

                // Compact queryable trace (summary only, no per-instruction details)
                let queryable_compact = litesvm::tracer::QueryableTrace::from_trace_context_compact(trace);

                // Show the execution summary
                println!("Queryable Trace {} Summary:", i);
                println!("  Result: {}", queryable_full.execution_summary.result);
                println!("  Total instructions: {}", queryable_full.execution_summary.total_instructions_executed);
                println!("  Functions called: {:?}", queryable_full.execution_summary.functions_called);
                println!("  Syscalls made: {:?}", queryable_full.execution_summary.syscalls_made);
                println!("  Accounts accessed: {:?}", queryable_full.execution_summary.accounts_accessed);

                // Show function index
                println!("\n  Function Index:");
                for (name, entry) in &queryable_full.function_index {
                    println!("    {} (PC 0x{:04x}): {}", name, entry.pc, entry.summary);
                    if !entry.syscalls.is_empty() {
                        println!("      syscalls: {:?}", entry.syscalls);
                    }
                }

                // Save full queryable trace
                let queryable_json = queryable_full.to_json().unwrap();
                let queryable_path = format!("trace_full_{}.json", i);
                fs::write(&queryable_path, &queryable_json).unwrap();
                println!("\n  Full trace saved to: {} ({} bytes)", queryable_path, queryable_json.len());

                // Save compact queryable trace
                let compact_json = queryable_compact.to_json().unwrap();
                let compact_path = format!("trace_compact_{}.json", i);
                fs::write(&compact_path, &compact_json).unwrap();
                println!("  Compact trace saved to: {} ({} bytes)", compact_path, compact_json.len());
            }

            // Also save raw trace for comparison
            let json_output = serde_json::to_string_pretty(&traces).unwrap();
            let output_path = "trace_raw.json";
            fs::write(output_path, &json_output).unwrap();
            println!("\nRaw trace saved to: {} ({} bytes)", output_path, json_output.len());
        }
    }

    #[cfg(not(feature = "semantic-tracer"))]
    {
        println!("ERROR: semantic-tracer feature not enabled!");
        println!("Run with: cargo run --example trace_program --features semantic-tracer");
    }
}

#[cfg(feature = "semantic-tracer")]
fn print_execution_summary(frames: &[litesvm::tracer::TracedCallFrame], indent: usize) {
    use litesvm::tracer::TraceEvent;

    for frame in frames {
        let prefix = "  ".repeat(indent + 1);

        // Count events by type
        let mut insn_count = 0;
        let mut mem_count = 0;
        let mut syscall_count = 0;
        let mut call_count = 0;
        let mut ret_count = 0;

        for event in &frame.events {
            match event {
                TraceEvent::Instruction(_) => insn_count += 1,
                TraceEvent::MemoryAccess(_) => mem_count += 1,
                TraceEvent::Syscall(_) => syscall_count += 1,
                TraceEvent::FunctionCall(_) => call_count += 1,
                TraceEvent::FunctionReturn(_) => ret_count += 1,
            }
        }

        println!(
            "{}Frame: {} (depth {}, PC {})",
            prefix,
            frame.symbol_name.as_deref().unwrap_or("<unknown>"),
            frame.depth,
            frame.start_pc
        );
        println!(
            "{}  Events: {} insn, {} mem, {} syscall, {} call, {} ret",
            prefix, insn_count, mem_count, syscall_count, call_count, ret_count
        );
        println!("{}  Compute units: {}", prefix, frame.frame_compute_units);

        // Show syscall details
        for event in &frame.events {
            if let TraceEvent::Syscall(syscall) = event {
                println!(
                    "{}  Syscall: {} -> {:?}",
                    prefix, syscall.name, syscall.return_value
                );
                if !syscall.args_decoded.is_empty() {
                    for (k, v) in &syscall.args_decoded {
                        // Truncate long values
                        let v_display = if v.len() > 60 {
                            format!("{}...", &v[..60])
                        } else {
                            v.clone()
                        };
                        println!("{}    {}: {}", prefix, k, v_display);
                    }
                }
            }
        }

        // Recurse into sub-calls
        if !frame.sub_calls.is_empty() {
            println!("{}  Sub-calls: {}", prefix, frame.sub_calls.len());
            print_execution_summary(&frame.sub_calls, indent + 2);
        }
    }
}
