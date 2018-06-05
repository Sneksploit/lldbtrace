if [ $# -eq 0 ]
  then
    echo "ERROR: First parameter should be the path to the target binary"
    exit 1
fi
symbols $1 -onlyFuncStarts | grep FunctionStarts | sed 's/^[[:space:]]*\(0x[0-9a-f]*\).*/\1/' > ./lldbtrace_sym.txt
if [ -s "lldbtrace_sym.txt" ]
then
  echo "Successfully dumped symbols to lldbtrace_sym.txt"
else
  echo "ERROR: Failed to dump symbols from file, is it a Mach-O binary?"
fi
