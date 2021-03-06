<div align="center">
  <h1>BitCamo</h1>
  <img align="center" width="280" src="https://github.com/juburr/bitcamo/raw/master/resources/bitcamo.png" alt="EXE File">
  <br />
  <b><i>Hiding malware in plain sight.</i></b><br /><br />
  BitCamo is an adversarial machine learning (AML) tool for modifying executables with the goal of evading malware detection systems. The initial version of this tool alters Windows PE files with the goal of evading the EMBER-trained MalConv model. The tool is designed to assist security researchers, AI/ML red team operators, and AV vendors. New contributors are welcome.<br /><br />
  <a href="https://github.com/pralab/secml_malware">SecML Malware</a> and <a href="https://github.com/bfilar/malware_rl">MalwareRL</a> are popular alternatives to this tool.
</div>

## Demo
<video src="https://user-images.githubusercontent.com/20321959/160679943-9c90956f-6e82-44e8-84c9-3fc3086322c1.mp4"></video>

## Attack Overview 

BitCamo is a gradient-based attack tool intended for use in whitebox attack scenarios. The current version is an implementation of Kreuk's FGSM overlay attack with greatly increased evasion rates and attack speeds. Selecting thousands of malicious samples (<1 MB) uniformly at random from the [SOREL-20M](https://github.com/sophos-ai/SOREL-20M) dataset results in a 100% evasion rate against the EMBER-trained MalConv model while using payload sizes of only 300 bytes on average. Attacks complete in a mere one second when using fixed size payloads, offering a massive performance improvement over existing tools. See the remarks on limitations below.

### PE File Modification
Most bytes within a Windows PE file cannot be freely modified without breaking functionality. BitCamo will attempt to insert payloads at unused locations throughout the file. The current version of this tool will only target the file overlay. The ability to use other payload locations will be included in future releases.

<div align="center">
  <img align="center" width="65%" src="https://github.com/juburr/bitcamo/raw/master/resources/bitcamo-attack-overview.png" alt="Attack Overview">
</div>

### Adversarial Attack Explanation
The payload contains a specially crafted set of bytes designed to fool MalConv. In our white-box attack scenario, these bytes are determined mathematically using the Fast Gradient Sign Method (FGSM). Before running the gradient attack, users have the ability to specify how the payload should be initialized. Previous attacks in the research literature use a randomized method, whereas this tool fills the payload with byte value `0xBF` by default, maximizing the likelihood of a succesful evasion. A primary obstacle that must be overcome is MalConv's non-differentiable embedding layer. Other tools use an L2 distance metric to map backwards across this layer, whereas this tool uses K-D trees to offer blazing fast lookup speeds.

### Limitations
The EMBER-trained MalConv model uses 1 MB input sizes. Although malware samples tend to be fairly small, note that BitCamo will not yet work against executables with larger file sizes, as it currently targets the file overlay. Future releases of the tool will target other sections of the PE file. Additional detection models will also be supported in future releases.

## Acknowledgements
This tool would not be possible without the amazing contributions to the research literature from the teams listed below.   

Defensive:
- MalConv ([Raff et al, 2017](https://arxiv.org/abs/1710.09435))
- EMBER-trained MalConv model ([Anderson & Roth, 2018](https://arxiv.org/abs/1804.04637))
- Pre-Detection Mechanism ([Chen et al., 2019](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8703786))

Offensive:
- Overlay attack ([Kolosnjaji et al., 2018](https://arxiv.org/abs/1803.04173))
- FGSM overlay attack ([Kreuk et al., 2019](https://arxiv.org/abs/1802.04528))
- One-shot FGSM slack attack ([Suciu et al., 2019](https://arxiv.org/abs/1810.08280))
- DOS header attacks ([Demetrio et al., 2021](https://arxiv.org/abs/2008.07125))
- K-D Tree reconstruction speedups ([Burr, 2022](https://scholar.dsu.edu/theses/378))
- Payload initialization methods ([Burr, 2022](https://scholar.dsu.edu/theses/378))
- Evasion of the pre-detection mechanism ([Burr, 2022](https://scholar.dsu.edu/theses/378))
- Payload size minimization algorithm ([Burr, 2022](https://scholar.dsu.edu/theses/378))

## Instructions
The provided Docker container is the quickest way for most users to get setup. Note that live malware samples are not included with the tool. You can download malware elsewhere at your own risk. Ten million malicious binaries are provided in the [SOREL-20M](https://github.com/sophos-ai/SOREL-20M) dataset by Sophos AI.

### Running the attack code using Docker
Ensure your machine has Docker installed and then follow the instructions below, being sure to replace `/host/malware/dir` with an absolute path to the directory containing your Windows PE malware samples.  
```
docker pull ghcr.io/juburr/bitcamo:latest
docker run -v /host/malware/dir:/home/nonroot/samples -it --entrypoint /bin/bash ghcr.io/juburr/bitcamo:latest
bitcamo.py samples/malicious_program.exe
```

### Running the attack code using Python virtual environments
Instructions will vary depending on your Linux distribution. The tool was developed using Python 3.8.  
Fedora 35: `dnf install python3.8 python3-devel gcc-c++`
```
git clone https://github.com/juburr/bitcamo.git
cd bitcamo
python3.8 -m venv .venv
source .venv/bin/activate
python3.8 -m pip install --upgrade pip setuptools wheel
python3.8 -m pip install -r requirements.txt
python3.8 bitcamo.py samples/malicious_program.exe
```

### Tips and Helpful CLI Flags

The usage instructions above show an attack against a single file. BitCamo can also process datasets by specifying an entire directory instead:  
`./bitcamo.py samples/malicious/sorel-20m`  

A payload size of 900 bytes is used by default. This can be changed with the `-p` flag, specifying that all samples should be attacked using a fixed-sized payload:  
`./bitcamo.py -p 1500 samples/malicious/sorel-20m`  

Iteratively increase the payload size in 50 bytes increments, to a maximum payload size of 2000 bytes. This is what allowed for a 100% evasion rate with only 300-byte payloads on average. Processing time will be increased from roughly 1 second to 5 seconds on average. Use the `-O` flag to optimize the payload size:  
`./bitcamo.py -O -p 2000 samples/malicious/sorel-20m`  

Try using a different payload initialization strategy by supplying the `-i` flag. By default BitCamo will initialize all bytes in the payload to 0xBF (191) before running FGSM. Other options include `random`, `psuedorandom`, and `weighted`. Previous research typically used the `random` technique. The `-i` flag will also work by supplying the integer representation of any byte value between 0-255.  For example, 0xAA (170) can be used by entering:  
`./bitcamo.py -i 170 samles/malicious/sorel-20m`  

The tool works in both directions. BitCamo can process a benign file and make it appear malicious without actually introducing malicious code. Use the `-b` flag to specify that inputs are benign:  
`./bitcamo.py -b samples/benign/windows-executables`  

Specify a different output directory using the `-o` flag:  
`./bitcamo.py -o samples/output/sorel-20m samples/malicious/sorel-20m`  

Other less important command line flags can be discovered in the help menu by supplying the `-h` or `--help` flags:  
`./bitcamo.py --help`

## References

Anderson, H., & Roth, P. (2018). EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models. doi:10.48550/arXiv.1804.04637

Burr, J. (2022). Improving Adverarial Machine Learning Attacks Against MalConv (Doctoral dissertation). Retrieved from https://scholar.dsu.edu/theses/378/

Chen, B., Ren, Z., Yu, C., Hussain, I., & Liu, J. (2019). Adversarial Examples for CNN-Based Malware Detectors. *IEEE Access, 7*, 54360-54371. doi:10.1109/ACCESS.2019.2913439

Demetrio, L., Coull, S., Biggio, B., Lagorio, G., Armando, A., & Roli, F. (2021). Adversarial EXEmples: A Survey and Experimental Evaluation of Practical Attacks on Machine Learning for Windows Malware Detection. *ACM Transactions on Privacy and Security, 24*(4), doi:10.1145/3473039

Kolosnjaji, B., Demontis, A., Biggio, B., Maiorca, D., Giacinto, G., Eckert, C., & Roli, F. (2018). Adversarial Malware Binaries: Evading Deep Learning for Malware Detection in Executables. doi:10.48550/arXiv.1803.04173

Kreuk, F., Barak, A., Aviv-Reuven, S., Baruch, M., Pinkas, B., & Keshet J. (2018). Deceiving End-to-End Deep Learning Malware Detectors using Adversarial Examples. doi:10.48550/arXiv.1802.04528

Raff, E., Barker, J., Sylvester, J., Brandon, R., Cantanzaro, B., & Nicholas, C. (2017). Malware Detection by Eating a Whole EXE. doi:10.48550/arXiv.1710.09435

Suciu, O., Coull, S., & Johns, J. (2019). Exploring Adversarial Examples in Malware Detection. doi:10.48550/arXiv.1810.08280
