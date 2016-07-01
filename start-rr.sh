sudo modprobe msr
sudo wrmsr -p 0 0xc0000105 0xff008000000e
sudo wrmsr -p 1 0xc0000105 0xff018000000e
sudo wrmsr -p 2 0xc0000105 0xff028000000e
sudo wrmsr -p 3 0xc0000105 0xff038000000e
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
sudo mount -t cpuset cpuset /cpusets
sudo mkdir /cpusets/one
echo 3 | sudo tee /cpusets/one/cpuset.cpus
echo $$ | sudo tee /cpusets/one/tasks
