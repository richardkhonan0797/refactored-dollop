# Convert [Open Vulnerability and Assessment Language](http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml) from XML to JSON

## Approach

I am using Python and [xmltodict](https://github.com/martinblech/xmltodict) is the package I use to help me convert XML to Python dictionary. It is easier to reconstruct the data in the form of Python dictionary. After converting to dictionary I create 3 dictionaries ``objects``, ``states`` and ``tests`` to store reference id and the value. And then I loop through the ``definition`` to create the result and reconstruct ``criteria``. I use recursion to reconstruct and traverse ``criteria`` because I find it is easier than using iteration. 

## Difficulties

- The size and data of the file is overwhelming and it is difficult to read.
- It took me a while to figure out the relation between states, objects and tests.
- Complex structure because there are a lot of nested elements.

## Run file

Default name for the input file is ``"com.redhat.rhsa-all.xml"``.  
Default name for the output file is ``"result.json"``.  
Edit in the script to change the file name.  

To run the script:
```console
foo@bar:~/path/to/project$ python convert.py 
```