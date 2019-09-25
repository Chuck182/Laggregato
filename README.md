# Laggregato

Laggregato stands for "Log Aggregator"
Parse a given log file and aggregate lines based on given fields for jointure. 
The utput format is a CSV file with ; delimiter. 

i.e. Can be used for firewall log traffic analysis (initial purpose of this tool).

Log fields format must be key=value or key="va lue"

![laggregato screenshot](laggregato.jpg) 

## Prerequisites

* An input log file formatted with key=value or key="va lue"
* A working python environment or a Windows OS using the Windows binary file [laggregato_0.3.zip](bin/windows/laggregato_0.3.zip).  

## Todo list

* Improve readme file 
* Specify the input log format. For now, only logs formatted with key=value or key="va lue" are working.

## Authors

* **Sylvain Benech** - *Initial work* - [Chuck182](https://github.com/Chuck182)

## License

This project is licensed under the GPL v3 License - see the [LICENSE.md](LICENSE.md) file for details

## Contribution

Feel free to contribute to this project. 
