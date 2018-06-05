# lldbtrace
Command scripts for lldb which logs all functions traversed at any given point during runtime.

Does not require insertion of probes (e.g. dtrace), or even a symbolicated binary!

## What it's for
lldbtrace assists in reverse engineering a binary by allowing you to automatically trace all code paths traversed by some particular functionality.

For example, you can set up the state of your application, start the trace, trigger the behaviour you're interested in, then log the functions executed.

## How it works
Software breakpoints are set on every function start address, and a lightweight script records for each thread which breakpoints were hit.

Two shell scripts are provided:

### getsymbols.sh
Run this initially with the path to a Mach-O binary as the first parameter.

It will dump the raw start addresses of all functions in the binary to cwd/lldbtrace_sym.txt

### lldbtrace.sh
After running the binary and preparing the state, run this script with the PID as the first parameter.

It will attach lldb with all the necessary breakpoints and continue execution.

Invoke the behaviour you want to trace, and then halt lldb with cmd+C.

Sometimes you have to hit cmd+C twice due to the python interpreter being the active context.

The resulting traces are dumped to cwd/lldbtrace_outputs/

You can continue lldb to continue tracing, and run the dumpbreaks command every time you want to dump the output.

## Limitations
- The output is just the raw addresses of the functions, I haven't resymbolicated them. Eventually I'd like it to support symbol information via a dSYM file as well.

- Output csv files still have the python array markup, i.e. square brackets and single quotes. If this is a problem let me know what formats you would prefer.

- I'd like to support iOS, but communicating with debugserver is extremely slow. There's no easy fix here unfortunately.

- Nothing will prevent it from blowing up if you attach it to the wrong binary for the dumped symbols. You'll probably just crash the target process.

- Use at your own risk. For example, the scripts will overwrite any generated files each time you run them; I'm not responsible for any lost work, or any system damage from their misuse.
