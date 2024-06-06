# IP Packet Identifier

A Python script for identifying and analyzing IP packets in PCAP files.

## Installation

1. Clone the repository:

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

The script will process the specified PCAP file and display statistics for each IP packet in the file.

```bash
usage: main.py [-h] [-f FILE_NAME] [--gui] [--cli] [--no-prettify] [-o OUTPUT]

Process a pcap file, extracting statistics.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE_NAME, --file_name FILE_NAME
                        The name of the pcap file to process.
  --gui                 Use graphical user interface.
  --cli                 Use command-line interface.
  --no-prettify         Do not prettify output.
  -o OUTPUT, --output OUTPUT
                        Output file name.
```

> By default, output is prettified. To disable prettification, use the --no-prettify option.
> And by default, output is saved to a file named stats.json. To specify a different output file, use the -o or --output option.

## Command-Line Interface
To use the command-line interface, run the main.py script with the --cli option and specify the name of the PCAP file to process using the -f or --file_name option:

```bash
python main.py --cli -f <pcap_file>
```

## Graphical User Interface
To use the graphical user interface, run the main.py script with the --gui option:

```bash
python main.py --gui
```

This will open a window with a file selection button and a process button. Click the file selection button to select a PCAP file to process, and then click the process button to display the statistics for each IP packet in the file.