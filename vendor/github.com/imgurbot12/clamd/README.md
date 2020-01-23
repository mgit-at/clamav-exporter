clamd
========

Interface to clamd (clamav daemon)

## Note:
This is a complete re-write of duchcoders original library. The unnessesarry use of channels has been removed and results are returned on completion in a list. Additional features have been added including the ScanBytes method for clamd which allows runtime evaluation of in memory bytes rather than from a file or having to open an stream handler.

## Copyright and license

Code and documentation copyright 2011-2014 Remco Verhoef. Code released under [the MIT license](LICENSE). 
