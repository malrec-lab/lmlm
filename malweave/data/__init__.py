"""Dataset acquisition, validation, splitting, and transformation code."""

from .io import (
    get_data_from_archives,
    get_processed_data,
    read_binary_file,
    read_binary_files,
    read_binary_files_lazy,
    read_binary_file_asynch,
    read_binary_files_asynch,
    read_binary_files_asynch_lazy,
    write_binary_file,
    write_binary_file_asynch,
    write_binary_files_asynch,
    Decompressor,
    decompress_error_resilient,
    decompress_collection,
)
from .executable_sections import get_executable_section, get_executable_section_bounds
from .pe_architecture import get_pe_architecture, is_32bit_x86
from .obfuscation import run_diec, is_obfuscated, is_obfuscated_file

__all__ = [
    "get_data_from_archives",
    "get_processed_data",
    "read_binary_file",
    "read_binary_files",
    "read_binary_files_lazy",
    "read_binary_file_asynch",
    "read_binary_files_asynch",
    "read_binary_files_asynch_lazy",
    "write_binary_file",
    "write_binary_file_asynch",
    "write_binary_files_asynch",
    "Decompressor",
    "decompress_error_resilient",
    "decompress_collection",
    "get_executable_section",
    "get_executable_section_bounds",
    "get_pe_architecture",
    "is_32bit_x86",
    "run_diec",
    "is_obfuscated",
    "is_obfuscated_file",
]
