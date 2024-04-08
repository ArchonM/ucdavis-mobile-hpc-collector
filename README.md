# ucdavis-mobile-hpv-collector

This repository severs as an automated toolchain for hpc events collection on Android platform, built by UC Davis ASEEC Lab.

## Getting Started

To use this tool, several steps are required: root access, simpleperf executable. This tool is tested on Pixel 4 with Android 10. For other devices, please refer to [simpleperf](https://android.googlesource.com/platform/system/extras/+/master/simpleperf/README.md) for more information.

### Prerequisites

* Root access
* simpleperf executable
* Android 10
* Python 3.6+

### Installing

To install simpleperf, you can either download it from [Android Studio](https://developer.android.com/) or build it from source. For building from source, please refer to [simpleperf](https://android.googlesource.com/platform/system/extras/+/master/simpleperf/README.md) for more information. The simpleperf executable can be found from the sdk you downloaded from Android Studio. The default path is 'sdk/ndk/[version you downloaded]/platform-tools/android/[version]/simpleperf/bin'. Depending on your testing environment, you may need to select the different binary executable.

### Environment Setup

1. Clone this repository to your local machine.
2. Copy the simpleperf executable to '/data/local/tmp' on you testing device.
3. Set the folder for apps to be tested in '~/app_lib/benign' and '~/app_lib/malicious'. If you would like to use an external folder rather than the default one, please modify the path in line 22 and 23 in auto_perf.sh.
4. Set the folder for the output of the tool in '~/output'. If you would like to use an external folder rather than the default one, please modify the path in line 25 in auto_perf.sh.

### Running the tool

To run the tool, simply execute the following command in the terminal:    
```bash auto_perf.sh```
This tool is deisgned to automatically all events that we found could have apprent pattern in previous research. Selected events to be collected should eb available for most testing environment. However, if any event is not available in your testing platform or you would like to add more events, modify the line 12 in auto_perf.sh.

### Data Process

If you are using the default setup or following the previous steps, the output of the tool will be stored in '~/output' and be recognized bu auto_process.py. If you used a customized configuration, you might want to change the setup in auto_process.py. To process the data, simply execute the following command in the terminal:    
```python auto_process.py```

### Planned Features

* Automatic Environment Setup for the tool: This feature will recognize your testing platform and thus select the correct simpleperf executable.
* Visualization: This feature will provide a visualization of the data collected by the tool and provide interactive interface.
* GUI?: Not sure if this is needed since the tool is designed for experienced users.