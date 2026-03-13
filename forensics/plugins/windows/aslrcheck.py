# searches all process to check for ASLR protection

from typing import Callable, List
from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions
from volatility3.plugins.windows import pslist

import io
import logging
import os
import pefile

vollog = logging.getLogger(__name__)

IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_FILE_RELOCS_STRIPPED = 0x0001

# pass PE file
def check_aslr(pe):
    pe.parse_data_directories([
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']
    ])
    dynamic = False
    stripped = False

    # check if PE file compiled with DYNAMIC base setting
    if (pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE):
        dynamic = True

    # check if file relocation data is stripped
    if (pe.FILE_HEADER.Characteristics & IMAGE_FILE_RELOCS_STRIPPED):
        stripped = True
    
    # if file is not compiled with DYNAMIC base or if the file is compiled with DYNAMIC base but the relocation data is stripped, then ASLR is not enabled
    if not dynamic or (dynamic and stripped):
        aslr = False
    else:
        aslr = True
    return aslr

# inherit from PluginInterface
class AslrCheck(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    @classmethod
    def get_requirements(cls):
        return [
            # memory layer requirement for the kernel, symbol table requirement for the Windows kernel, plugin requirement for pslist to get the list of processes, and a list requirement for process IDs to include in the scan (optional)
            # requirements.TranslationLayerRequirement(
            #                                         name = 'primary', 
            #                                         description = 'Memory layer for the kernel', 
            #                                         architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(
                                                name = 'nt_symbols', 
                                                description = 'Windows kernel symbols'),
            requirements.PluginRequirement(
                                            name = 'pslist', 
                                            plugin = pslist.PsList, 
                                            version=(3, 0, 1)),
            requirements.ListRequirement(
                                            name = 'pid', 
                                            element_type = int, 
                                            description = "Process IDs to include (all other processes are excluded)", 
                                            optional = True),
            requirements.ModuleRequirement(
                                            name = 'kernel',
                                            description= 'Windows kernel',
                                            architectures=["Intel32", "Intel64"])
        ]

    # exclude processes that are not in the list of process IDs to include (if provided), otherwise include all processes
    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[interfaces.objects.ObjectInterface], bool]:
        # dont filter anything
        filter_func = lambda _: False
        # handle case where pid_list is None and filter out None values from pid_list
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        # if filter_list is not empty, create filter function to exclude processes with IDs in filter_list
        if filter_list:
            filter_func = lambda x: x.UniqueProcessId not in filter_list
        return filter_func

    def _generator(self, procs):
        # data structure used while looping over each process in memory
        pe_table_name = intermed.IntermediateSymbolTable.create(
                                                                    self.context, 
                                                                    self.config_path, 
                                                                    "windows", 
                                                                    "pe", 
                                                                    class_types=extensions.pe.class_types)

        procnames = list()
        for proc in procs:
            procname = proc.ImageFileName.cast(
                                                "string", 
                                                max_length = proc.ImageFileName.vol.count, 
                                                errors = "replace")
            if procname in procnames:
                continue
            procnames.append(procname)

            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as e:
                vollog.error(f"Process {proc_id}: invalid address {e} in layer {e.layer_name}")
                continue

            # object for Process Environment Block, memory region associated with process containing various process information
            peb = self.context.object(
                                        self.config['nt_symbols'] + 
                                        constants.BANG + 
                                        "_PEB", layer_name = proc_layer_name, 
                                        offset = proc.Peb)

            try:
                dos_header = self.context.object(
                                                pe_table_name + 
                                                constants.BANG + "_IMAGE_DOS_HEADER", 
                                                layer_name = proc_layer_name, 
                                                offset = peb.ImageBaseAddress)
            except Exception as e:
                continue
        
            pe_data = io.BytesIO()
            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)
            # write PEB data to a file like object
            pe_data_raw = pe_data.getvalue()
            pe_data.close()

            try:
                # use PEB data to create a PE object
                pe = pefile.PE(data=pe_data_raw)
            except Exception as e:
                continue
            
            # pass PE object to check_aslr function to check if ASLR is enabled for the process and yield results
            aslr = check_aslr(pe)

            yield (0, (proc_id, procname, format_hints.Hex(pe.OPTIONAL_HEADER.ImageBase),aslr))

    def run(self):
        # get list of prcesses
        procs = pslist.PsList.list_processes (self.context, 
                                            # self.config['primary'], 
                                            # self.config['nt_symbols'], 
                                            self.config['kernel'],
                                            filter_func = 
                                            self.create_pid_filter(self.config.get('pid', None)))
        # return data from generator
        return renderers.TreeGrid([
            ("PID", int),
            ("Process Name", str),
            ("Image Base", format_hints.Hex),
            ("ASLR Enabled", bool)
        ], self._generator(procs))