import cmd, sys, copy
# from trace_transaction import color_normal

class MacaronShell(cmd.Cmd):

    color_normal = '\033[31m\033[40m'
    clear = '\033c\033'

    intro = f'{color_normal}Macaron Navigator V 0.1'
    prompt = '>:'
    index = 0
    step_trace = []


    # User commands
    def do_next(self, arg):
        self.index += 1
    
    def do_prev(self, arg):
        self.index -= 1

    def do_quit(self, arg):
        exit(0)


    # Utility
    def load_trace(self, step_trace):
        self.step_trace = copy.deepcopy(step_trace)

    def preloop(self):
        print(self.step_trace[0])
        print(f'Controls: (n)ext step - (p)revious step - (q)uit')
    
    def postcmd(self, stop, line):
        print(f'{self.clear}{self.color_normal}') # Reset Terminal

        if self.index < 0:
            self.index = 0
            print(self.step_trace[self.index])
            print('Reached the start of the trace.')
        elif self.index >= len(self.step_trace):
            self.index = len(self.step_trace) - 1
            print(self.step_trace[self.index])
            print('Reached the end of the trace.')
        else:
            print(self.step_trace[self.index])

        print(f'Controls: (n)ext step - (p)revious step - (q)uit')
        