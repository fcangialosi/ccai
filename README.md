ccai
====

### Setup
1. pull submodules
2. (install rust?)
3. build hwfq: `cargo b --features="bin" --release`
4. fix hwfq path inside complex.py if necessary
5. install python dependencies: mininet (manual git clone and install from website), ptpython (pip install)

### Run

`sudo python3 complex.py {exp_dir}`

This creates two dirs `exp_dir` (hwfq output) and `pcaps`, which contains live updating tcpdumps (so you can `tail -f` them) on the interfaces

