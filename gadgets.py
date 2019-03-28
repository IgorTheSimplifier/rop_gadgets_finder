import sys
from capstone import *
import binascii

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

##############################################################
# takes a string of arbitrary length and formats it 0x for Capstone
def convertXCS(s):
	if len(s) < 2: 
		print "Input too short!"
		return 0
	
	if len(s) % 2 != 0:
		print"Input must be multiple of 2!"
		return 0

	conX = ''
	
	for i in range(0, len(s), 2):
		b = s[i:i+2]
		b = chr(int(b, 16))
		conX = conX + b
	return conX
##############################################################
# 

def getHexStreamsFromElfExecutableSections(filename):
	#print "Processing file:", filename
	with open(filename, 'rb') as f:
		elffile = ELFFile(f)
		
		execSections = []
		goodSections = [".text"] #[".interp", ".note.ABI-tag", ".note.gnu.build-id", ".gnu.hash", ".hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rela.dyn", ".rela.plt", ".init", ".plt", ".text", ".fini", ".rodata", ".eh_frame_hdr", ".eh_frame"]
		checkedSections = [".init", ".plt", ".text", ".fini"]
		
		for nsec, section in enumerate(elffile.iter_sections()):

			# check if it is an executable section containing instructions
			
			# good sections we know so far:
			#.interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .text .fini .rodata .eh_frame_hdr .eh_frame
		
			if section.name not in goodSections:
				continue
			
			# add new executable section with the following information
			# - name
			# - address where the section is loaded in memory
			# - hexa string of the instructions
			name = section.name
			addr = section['sh_addr']
			byteStream = section.data()
			hexStream = binascii.hexlify(byteStream)
			newExecSection = {}
			newExecSection['name'] = name
			newExecSection['addr'] = addr
			newExecSection['hexStream'] = hexStream
			execSections.append(newExecSection)

		return execSections


if __name__ == '__main__':
	if sys.argv[1] == '--length':
		md = Cs(CS_ARCH_X86, CS_MODE_64)
		gadget_size = int(sys.argv[2])
		for filename in sys.argv[3:]:
			r = getHexStreamsFromElfExecutableSections(filename)
			for s in r:
				hexdata = s['hexStream']
				
				#will contain all gadgets in hex representation
				gadgets_hex_set 		= set()
				
				#list of possible ret hex values
				returnHex				= ["c3", "cb"]
				
				lastReturnPos			= 0
				for iterator in returnHex:
					while ( hexdata.find(iterator, lastReturnPos) != -1 ):
						pos = hexdata.find(iterator, lastReturnPos)

						# if we have found ret hex value but
						# the size of gadget that we need  is bigger 
						if (gadget_size * 2 > pos):
							lastReturnPos = pos + 2
							continue
						
						# getting potential gadget (in hex string representation)
						potential_gadget_hex 	= hexdata[pos - gadget_size * 2: pos + 2]
						lastReturnPos 			= pos + 2

						# getting the string of commands of our potential gadget
						potential_gadget = []
						for (address, size, mnemonic, op_str) in md.disasm_lite(convertXCS(potential_gadget_hex), 0):
							if (mnemonic == "jmp" or mnemonic == "call"):
								potential_gadget = []
								break
							potential_gadget.append(mnemonic + " " + op_str)	
						
						# checking if potential gadget is really gadget (ends with ret instruction)
						if (potential_gadget != []):
							if (potential_gadget[len(potential_gadget) - 1] == unicode("ret ","utf-8")):
								gadgets_hex_set.add(potential_gadget_hex)
				
				print '\n'.join(gadgets_hex_set);
				print "Number of unique gadgets: " + str(len(gadgets_hex_set))