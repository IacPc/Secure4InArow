# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

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
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug"

# Include any dependencies generated for this target.
include CMakeFiles/Client.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Client.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Client.dir/flags.make

CMakeFiles/Client.dir/Client/Client.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/Client/Client.cpp.o: ../Client/Client.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Client.dir/Client/Client.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/Client/Client.cpp.o -c "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/Client.cpp"

CMakeFiles/Client.dir/Client/Client.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/Client/Client.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/Client.cpp" > CMakeFiles/Client.dir/Client/Client.cpp.i

CMakeFiles/Client.dir/Client/Client.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/Client/Client.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/Client.cpp" -o CMakeFiles/Client.dir/Client/Client.cpp.s

CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.o: ../Libraries/SignatureManager.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.o -c "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/SignatureManager.cpp"

CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/SignatureManager.cpp" > CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.i

CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/SignatureManager.cpp" -o CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.s

CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.o: ../Libraries/SymmetricEncryptionManager.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.o -c "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/SymmetricEncryptionManager.cpp"

CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/SymmetricEncryptionManager.cpp" > CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.i

CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/SymmetricEncryptionManager.cpp" -o CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.s

CMakeFiles/Client.dir/Client/CertificateManager.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/Client/CertificateManager.cpp.o: ../Client/CertificateManager.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/Client.dir/Client/CertificateManager.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/Client/CertificateManager.cpp.o -c "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/CertificateManager.cpp"

CMakeFiles/Client.dir/Client/CertificateManager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/Client/CertificateManager.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/CertificateManager.cpp" > CMakeFiles/Client.dir/Client/CertificateManager.cpp.i

CMakeFiles/Client.dir/Client/CertificateManager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/Client/CertificateManager.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/CertificateManager.cpp" -o CMakeFiles/Client.dir/Client/CertificateManager.cpp.s

CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.o: ../Client/ServerConnectionManager.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.o -c "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/ServerConnectionManager.cpp"

CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/ServerConnectionManager.cpp" > CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.i

CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/ServerConnectionManager.cpp" -o CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.s

CMakeFiles/Client.dir/Client/ClientMain.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/Client/ClientMain.cpp.o: ../Client/ClientMain.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/Client.dir/Client/ClientMain.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/Client/ClientMain.cpp.o -c "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/ClientMain.cpp"

CMakeFiles/Client.dir/Client/ClientMain.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/Client/ClientMain.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/ClientMain.cpp" > CMakeFiles/Client.dir/Client/ClientMain.cpp.i

CMakeFiles/Client.dir/Client/ClientMain.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/Client/ClientMain.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Client/ClientMain.cpp" -o CMakeFiles/Client.dir/Client/ClientMain.cpp.s

CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.o: ../Libraries/DiffieHellamnnManager.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.o -c "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/DiffieHellamnnManager.cpp"

CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/DiffieHellamnnManager.cpp" > CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.i

CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/Libraries/DiffieHellamnnManager.cpp" -o CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.s

# Object files for target Client
Client_OBJECTS = \
"CMakeFiles/Client.dir/Client/Client.cpp.o" \
"CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.o" \
"CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.o" \
"CMakeFiles/Client.dir/Client/CertificateManager.cpp.o" \
"CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.o" \
"CMakeFiles/Client.dir/Client/ClientMain.cpp.o" \
"CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.o"

# External object files for target Client
Client_EXTERNAL_OBJECTS =

Client: CMakeFiles/Client.dir/Client/Client.cpp.o
Client: CMakeFiles/Client.dir/Libraries/SignatureManager.cpp.o
Client: CMakeFiles/Client.dir/Libraries/SymmetricEncryptionManager.cpp.o
Client: CMakeFiles/Client.dir/Client/CertificateManager.cpp.o
Client: CMakeFiles/Client.dir/Client/ServerConnectionManager.cpp.o
Client: CMakeFiles/Client.dir/Client/ClientMain.cpp.o
Client: CMakeFiles/Client.dir/Libraries/DiffieHellamnnManager.cpp.o
Client: CMakeFiles/Client.dir/build.make
Client: CMakeFiles/Client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_8) "Linking CXX executable Client"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Client.dir/build: Client

.PHONY : CMakeFiles/Client.dir/build

CMakeFiles/Client.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Client.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Client.dir/clean

CMakeFiles/Client.dir/depend:
	cd "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto" "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto" "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug" "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug" "/Users/lauralemmi/Google Drive/università/CE/Cybersecurity/Progetto/cmake-build-debug/CMakeFiles/Client.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/Client.dir/depend

