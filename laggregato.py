import sys  
import os
import getopt
import re
import hashlib

inputfile = ''
outputfile = ''
joinfields = []
filterfields = []
aggregations = {}
sorted_aggregations = []
delimiter = ' '
equalizer = '='

class Aggregation:
    def __init__(self, h, t):
        self._hash = h
        self._text = t
        self._count = 1
    
    @property
    def hash(self):
        return self._hash

    @property
    def text(self):
        return self._text

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, input_count):
        self._count = input_count
    
    def add_occurence(self):
        self._count = self._count + 1
        
def display_usage_exception():
    print ('Wrong arguments. Exiting.')
    print ('Check laggregato.exe --help for more info.')

def display_help():
    print ('NAME')
    print ('       laggregato - stands for "log aggregator"')
    print ('       Parse a given log file and aggregate lines based')
    print ('       on given fields for jointure.')
    print ('       The output format is a csv file with ; delimiter.')
    print ('       i.e. Can be used for firewall log traffic analysis.')
    print ('       Log fields format must be key=value or key=\"Val ue\"')
    print ('\nUSAGE')
    print ('       laggregato.exe -h (display this current manual)')
    print ('       laggregato.exe --help (like -h)')
    print ('       laggregato.exe -i <inputfile> -o <outputfile> -j <filed_list> [OPTS]')
    print ('\nMANDATORY ARGUMENTS')
    print ('       -i, --ifile')
    print ('              Path of the input file.')
    print ('              The input log file must be readable and in text format.')
    print ('\n       -o, --ofile')
    print ('              Path of the output file.')
    print ('              The output csv file folder must be writable.')
    print ('\n       -j')
    print ('              List of fields for jointure in one of the following format : ')
    print ('                srcip,dstip,action')
    print ('                "srcip","dstip","action"')
    print ('              Be careful, if the quotes really exist in the log file,')
    print ('              they must be escaped with \\')
    print ('              i.e. \\"Field Name Here\\"')
    print ('\nOPTIONS')
    print ('       -f')
    print ('              Optional list of patterns.')
    print ('              This allows to work on a subpart of the log file.')
    print ('              Must be in the following format :')
    print ('                type=\\"traffic\\",action=\\"deny\\"')
    print ('              Be careful, if the quotes really exist in the pattern,')
    print ('              they must be escaped with \\')
    print ('              i.e. action=\\"deny\\"')


        
def check_args(argv):
    global inputfile
    global outputfile
    global joinfields
    global filterfields
    
    try:
        opts, args = getopt.getopt(argv,"hi:o:j:f:",["help","ifile=","ofile="])
    except getopt.GetoptError:
        display_usage_exception()
        sys.exit(2)
        
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            display_help()
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg.strip()
        elif opt in ("-o", "--ofile"):
            outputfile = arg.strip()
        elif opt == "-j":
            joinfields = arg.split(",") 
        elif opt == "-f":
            filterfields = arg.split(",") 

            
    if (inputfile == "" or outputfile == "" or len(joinfields) == 0):
        display_usage_exception()
        sys.exit(2)
                        
    print ('  => Input file :',inputfile)
    print ('  => Output file :',outputfile)
    print ('  => Join fields :',joinfields)
    print ('  => Filter fields :',filterfields)
    
    if not os.path.isfile(inputfile):
        print("Cannot read input file. Exiting.")
        sys.exit(2)
        
    try:
        f= open(outputfile,"w+")
        f.close() 
    except:
        print("Cannot write into output file. Exiting.")
        sys.exit(2)

def is_matching_filters(line):
    matching_filter = True
    for filter in filterfields:
        z = re.search(filter, line)
        if not z:
            matching_filter = False
    return matching_filter


def extract_aggregation_from_line(line):
    global aggregations
    text = ""
    for joinfield in joinfields:
        z = re.search(r'\s+'+joinfield+'=(\S*)\s+', line)
        if z:
            text = text + z.group(1) + ';'
        else:
            text = text + ';'
#    print ("Text : ", text)
    hash = hashlib.md5(text.encode('utf-8')).hexdigest()
#    print (text+"  <==>  "+line)
    
    if hash not in aggregations:
        aggregations[hash] = Aggregation(hash, text) 
    else:
        aggregations[hash].add_occurence()

def analyse_log_file():
    print ()
    print ("Analysing log file...")
    print ("Looking for aggregations...")
    with open(inputfile) as fp:
        for line in fp:
            if (is_matching_filters(line)):
                extract_aggregation_from_line(line)
            
def sort_results():
    global sorted_aggregations
    print ("Sorting results...")
    sorted_aggregations = list(aggregations.values())
    sorted_aggregations.sort(key=lambda x: x.count, reverse=True)
              
def export_results():
    print ("Exporting results...")

    try:
        f = open(outputfile,"w+")
    except:
        print("Fatal error. Cannot write into output file. Exiting.")
        sys.exit(2)
    
    # Display header
    header = ""
    for joinfield in joinfields:
        header = header + joinfield
        header = header + ";"
    header = header + "count"
    f.write(header+'\n')
#    print (header)
    
    # Display lines
    number_of_logs = 0
    for agg in sorted_aggregations:
        f.write(agg.text+str(agg.count)+'\n')
        number_of_logs = number_of_logs + agg.count
#        print (agg.text+str(agg.count))
    
    f.close()
    
    print ()
    print ("  => "+str(len(sorted_aggregations))+" log aggregations have been exported to "+outputfile+".")
    print ("  => "+str(number_of_logs)+" logs are involved in these aggregations.")

def main():
    print("laggregato -  (v0.3)")
    print("Written by Sylvain Benech")
    print()

    check_args(sys.argv[1:])
    analyse_log_file()
    sort_results()
    export_results()

if __name__== "__main__":
    main()
