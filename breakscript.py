#!/usr/bin/python
'''
    The MIT License (MIT)
    Copyright (c) 2018 @sneksploit of sneksploit.com
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
'''

import lldb
import optparse
import commands
import shlex
import os

files = {}              # Container for the trace hits
full_logging = False    # TRUE=log full stack trace, FALSE=log address only (recommended)
aslr = 0                # Will be updated automatically with ASLR slide
DEBUG = True            # Additional print output
name = ""             # Holds the main module name, used as an output file prefix


def dump_output(debugger, command, result, internal_dict):
    """
    Write a function trace to output directory as csv, one file per thread.
    """

    errtext = "Usage: dumpbreaks -o /path/to/outputdir"
    command_args = shlex.split(command)
    parser = create_output_parser()
    try:
        (options, args) = parser.parse_args(command_args)
        outpath=options.outdir
    except:
        print("No directory specified. Defaulting to ./lldbtrace_outputs")

    if not outpath:
        outpath = './lldbtrace_outputs/' # default output directory
    if not os.path.exists(outpath):
        try:
            os.makedirs(outpath)
        except:
            print("Problem creating output directory " + outpath)
            return

    err = False
    for key in files.keys():
        # 'with' is causing issues as LLDB can use python2 interpreter; do it the old way
        try:
            writepath = outpath + name + "_thread_" + str(key) + ".csv"
            f = open(writepath, "w+")
            try:
                f.write(str(files[key]))
                print("Written to " + writepath)
            except:
                print("Failed to write to file at " + str(writepath))
                err = True
            finally:
                f.close()
            if err:
                break
        except IOError:
            print("Failed to create file at " + str(writepath))
            break


def store_at_break(frame, bp_loc, dict):
    """
    LLDB breakpoint callback.
    Log the breakpoint location so we can recall it later. Separates breakpoints by thread.
    Caution: this function should be as lightweight as possible, print only where necessary.
    """
    global files
    global aslr
    global DEBUG

    try:
        if full_logging:
            files[frame.GetThread().GetIndexID()].append(lldb.frame)
        else:
            files[frame.GetThread().GetIndexID()].append(hex(int(bp_loc.GetAddress()) - aslr))
    except:
        print("New thread: " + str(frame.GetThread().GetIndexID()))
        if full_logging:
            if DEBUG:
                print("Making array for full logging")
            files[frame.GetThread().GetIndexID()] = [lldb.frame]
            if DEBUG:
                print("Done making array");
        else:
            if DEBUG:
                print("Making array for partial logging")
            files[frame.GetThread().GetIndexID()] = [hex(int(bp_loc.GetAddress())  - aslr)]
            if DEBUG:
                print("Done making array");
    return False # continue execution


def set_breaks(debugger, command, result, internal_dict):
    """
    Set breakpoints on every address in the symbols file. Automatically adjusts for ASLR.
    Attaches a breakpoint command which remembers the address+thread, and continues execution.
    """
    global aslr
    global name

    usage = "Usage: breakscript -i /path/to/symbols_file.txt"
    command_args = shlex.split(command)
    parser = create_input_parser()
    try:
        (options, args) = parser.parse_args(command_args)
        path=options.infile
    except:
        result.SetError("Failed to get filename. " + usage)
        return

    try:
        # LLDB uses python2, no with() unfortunately
        symfile = open(path, 'r')
        print "file opened"
        target = debugger.GetSelectedTarget()
        print "target obtained: " + str(target)
        name = str(target)
        bp = None
        if target:
            # Must determine ASLR slide to set breakpoints at the correct locations
            module = target.GetModuleAtIndex(0)
            print "module obtained: " + str(module)
            aslr = module.FindSection("__TEXT").get_addr().__get_load_addr_property__()
            print "aslr slide obtained: " + hex(aslr)
            aslr = aslr % 0x100000000
            print "aslr now: " + hex(aslr)
            for line in symfile:
                bp = target.BreakpointCreateByAddress(int(line,16) + aslr)
                bp.SetScriptCallbackFunction('breakscript.store_at_break')
            print("Finished setting breakpoints")
        else:
            print("No target available")
    except:
        print("Problem opening file. Did you run getsymbols.sh? " + usage)
    return

def create_input_parser():
    parser = optparse.OptionParser(description='''Sets a logger for all breakpoints in the input file specified by -i'''  , prog='breakscript',usage="usage setbreaks -i /path/to/lldbtrace_sym.txt")
    parser.add_option('-i', '--input', type='string', dest='infile', help='Input file containing addresses separated by newline')
    return parser

def create_output_parser():
    parser = optparse.OptionParser(description='''Outputs logs to directory specified by -o'''  , prog='dumpbreaks',usage="usage dumpbreaks -o /path/to/output")
    parser.add_option('-o', '--output', type='string', dest='outdir', help='Output directory')
    return parser


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f breakscript.set_breaks setbreaks')
    debugger.HandleCommand('command script add -f breakscript.dump_output dumpbreaks')
