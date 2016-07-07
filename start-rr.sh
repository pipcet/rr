sudo modprobe msr
sudo wrmsr -p 0 0xc0000105 0xff00e000000e
sudo wrmsr -p 1 0xc0000105 0xff01e000000e
sudo wrmsr -p 2 0xc0000105 0xff02e000000e
sudo wrmsr -p 3 0xc0000105 0xff03e000000e
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
sudo mount -t cpuset cpuset /cpusets
sudo mkdir /cpusets/one
echo 3 | sudo tee /cpusets/one/cpuset.cpus
echo $$ | sudo tee /cpusets/one/tasks
