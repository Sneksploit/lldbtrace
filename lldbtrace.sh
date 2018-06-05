if [ $# -eq 0 ]
  then
    echo "ERROR: Please supply a PID as the first parameter"
    exit 1
fi
eval "lldb -p $1 -s trace.cmds"
