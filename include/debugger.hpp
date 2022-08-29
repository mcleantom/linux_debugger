#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "breakpoint.hpp"

namespace minidbg {
    class debugger {
        public:
            debugger(std::string prog_name, pid_t pid) : m_prog_name{std::move(prog_name)}, m_pid{pid} {

            }
            
            void run();
            void set_breakpoint_at_address(std::intptr_t addr);
        private:
            std::string m_prog_name;
            std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
            pid_t m_pid;
            void handle_command(const std::string& line);
            void continue_execution();
    };

    void debugger::set_breakpoint_at_address(std::intptr_t addr) {
        std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
        breakpoint bp {m_pid, addr};
        bp.enable();
        m_breakpoints.insert({addr, bp});
    }

    void debugger::run() {
        /*
        Wait until the child process has finished launching and then keep on getting input
        from linenoise until we get an EOF (ctrl+d)
        */
        int wait_status;
        auto options = 0;
        waitpid(m_pid, &wait_status, options);

        char* line = nullptr;
        while((line = linenoise("minidbg> ")) != nullptr) {
            handle_command(line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
        }

    }

    void debugger::handle_command(const std::string& line) {
        auto args = split(line, ' ');
        auto command = args[0];

        if (is_prefix(command, "continue")) {
            continue_execution();
        }
        else if (is_prefix(command, "break")) {
            std::string addr {args[1], 2}; // Assume 0xADDRESS
            set_breakpoint_at_address(std::stol(addr, 0, 16));
        }
        else {
            std::cerr << "Unknown command \n";
        }
    }

    void debugger::continue_execution() {
        ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

        int wait_status;
        auto options = 0;
        waitpid(m_pid, &wait_status, options);
    }
}

#endif