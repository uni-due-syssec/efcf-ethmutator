/*
 * web3.js No-Reentrancy Exploit Generated by EF/CF Attack Contract Synthesizer
 * (warning only works for the most basic transactions)
 *
 * The original test case was executed with the following environment:
 * block number: +{{ header.get_number() }}
 * timestamp: +{{ header.get_timestamp() }}
 * gas limit: {{ header.get_gas_limit() }}
 * difficulty: {{ header.get_difficulty() }}
 * initial balance: {{ header.get_initial_ether()|from_call_value }} wei
 *
 */

attackers = eth.accounts; // TODO: change if needed
targets = [
  // TODO: fill out
]

const REQUIRED_BUDGET = {{required_budget|as_hex}}; /* equals {{required_budget|wei_to_ether }} */
{%- if header.initial_ether > 0 %}
const INITIAL_ETHER = {{header.get_initial_ether()|from_call_value}};
{%- endif %}
{%- for call in fc.txs %}
{%- let ba = call.header.block_advance %}
{%- if ba > 0 %}
/* WARNING: Call should advance blockchain state:
 * block number += {{ ba }}
 * timestamp += {{ ba|advance_to_time }}
 */
console.log("should be waiting for {{ ba|advance_to_time }} ");
/*sleep(???)*/
{%- endif %}
{%- if contractinfo.is_some() %}
/*
 * {{- call.input|abi_format(contractinfo) }}
 */
{%- endif %}
console.log("sending transaction");
eth.sendTransaction({
  from: attackers[{{ call.header.get_sender_select() }} % attackers.length],
  data: {{ call.input|to_hexstring_js }},
  value: {{ call.header.get_packed_call_value()|from_call_value }},
  to: targets[{{ call.header.get_receiver_select() }} % targets.length],
  gasPrice:0
})

{%- endfor %}
