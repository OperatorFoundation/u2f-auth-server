# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/brandon/u2f-server2

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/brandon/u2f-server2

# Include any dependencies generated for this target.
include CMakeFiles/u2f_server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/u2f_server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/u2f_server.dir/flags.make

CMakeFiles/u2f_server.dir/comm-2fserver.c.o: CMakeFiles/u2f_server.dir/flags.make
CMakeFiles/u2f_server.dir/comm-2fserver.c.o: comm-2fserver.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brandon/u2f-server2/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/u2f_server.dir/comm-2fserver.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/u2f_server.dir/comm-2fserver.c.o   -c /home/brandon/u2f-server2/comm-2fserver.c

CMakeFiles/u2f_server.dir/comm-2fserver.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/u2f_server.dir/comm-2fserver.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/brandon/u2f-server2/comm-2fserver.c > CMakeFiles/u2f_server.dir/comm-2fserver.c.i

CMakeFiles/u2f_server.dir/comm-2fserver.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/u2f_server.dir/comm-2fserver.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/brandon/u2f-server2/comm-2fserver.c -o CMakeFiles/u2f_server.dir/comm-2fserver.c.s

CMakeFiles/u2f_server.dir/comm-2fserver.c.o.requires:

.PHONY : CMakeFiles/u2f_server.dir/comm-2fserver.c.o.requires

CMakeFiles/u2f_server.dir/comm-2fserver.c.o.provides: CMakeFiles/u2f_server.dir/comm-2fserver.c.o.requires
	$(MAKE) -f CMakeFiles/u2f_server.dir/build.make CMakeFiles/u2f_server.dir/comm-2fserver.c.o.provides.build
.PHONY : CMakeFiles/u2f_server.dir/comm-2fserver.c.o.provides

CMakeFiles/u2f_server.dir/comm-2fserver.c.o.provides.build: CMakeFiles/u2f_server.dir/comm-2fserver.c.o


CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o: CMakeFiles/u2f_server.dir/flags.make
CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o: plugin-u2f-server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brandon/u2f-server2/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o   -c /home/brandon/u2f-server2/plugin-u2f-server.c

CMakeFiles/u2f_server.dir/plugin-u2f-server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/u2f_server.dir/plugin-u2f-server.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/brandon/u2f-server2/plugin-u2f-server.c > CMakeFiles/u2f_server.dir/plugin-u2f-server.c.i

CMakeFiles/u2f_server.dir/plugin-u2f-server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/u2f_server.dir/plugin-u2f-server.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/brandon/u2f-server2/plugin-u2f-server.c -o CMakeFiles/u2f_server.dir/plugin-u2f-server.c.s

CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.requires:

.PHONY : CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.requires

CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.provides: CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.requires
	$(MAKE) -f CMakeFiles/u2f_server.dir/build.make CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.provides.build
.PHONY : CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.provides

CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.provides.build: CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o


CMakeFiles/u2f_server.dir/support.c.o: CMakeFiles/u2f_server.dir/flags.make
CMakeFiles/u2f_server.dir/support.c.o: support.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brandon/u2f-server2/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/u2f_server.dir/support.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/u2f_server.dir/support.c.o   -c /home/brandon/u2f-server2/support.c

CMakeFiles/u2f_server.dir/support.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/u2f_server.dir/support.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/brandon/u2f-server2/support.c > CMakeFiles/u2f_server.dir/support.c.i

CMakeFiles/u2f_server.dir/support.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/u2f_server.dir/support.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/brandon/u2f-server2/support.c -o CMakeFiles/u2f_server.dir/support.c.s

CMakeFiles/u2f_server.dir/support.c.o.requires:

.PHONY : CMakeFiles/u2f_server.dir/support.c.o.requires

CMakeFiles/u2f_server.dir/support.c.o.provides: CMakeFiles/u2f_server.dir/support.c.o.requires
	$(MAKE) -f CMakeFiles/u2f_server.dir/build.make CMakeFiles/u2f_server.dir/support.c.o.provides.build
.PHONY : CMakeFiles/u2f_server.dir/support.c.o.provides

CMakeFiles/u2f_server.dir/support.c.o.provides.build: CMakeFiles/u2f_server.dir/support.c.o


# Object files for target u2f_server
u2f_server_OBJECTS = \
"CMakeFiles/u2f_server.dir/comm-2fserver.c.o" \
"CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o" \
"CMakeFiles/u2f_server.dir/support.c.o"

# External object files for target u2f_server
u2f_server_EXTERNAL_OBJECTS =

libu2f_server.so: CMakeFiles/u2f_server.dir/comm-2fserver.c.o
libu2f_server.so: CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o
libu2f_server.so: CMakeFiles/u2f_server.dir/support.c.o
libu2f_server.so: CMakeFiles/u2f_server.dir/build.make
libu2f_server.so: CMakeFiles/u2f_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/brandon/u2f-server2/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C shared library libu2f_server.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/u2f_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/u2f_server.dir/build: libu2f_server.so

.PHONY : CMakeFiles/u2f_server.dir/build

CMakeFiles/u2f_server.dir/requires: CMakeFiles/u2f_server.dir/comm-2fserver.c.o.requires
CMakeFiles/u2f_server.dir/requires: CMakeFiles/u2f_server.dir/plugin-u2f-server.c.o.requires
CMakeFiles/u2f_server.dir/requires: CMakeFiles/u2f_server.dir/support.c.o.requires

.PHONY : CMakeFiles/u2f_server.dir/requires

CMakeFiles/u2f_server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/u2f_server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/u2f_server.dir/clean

CMakeFiles/u2f_server.dir/depend:
	cd /home/brandon/u2f-server2 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/brandon/u2f-server2 /home/brandon/u2f-server2 /home/brandon/u2f-server2 /home/brandon/u2f-server2 /home/brandon/u2f-server2/CMakeFiles/u2f_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/u2f_server.dir/depend

