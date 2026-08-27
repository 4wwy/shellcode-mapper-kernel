# Kernel-Mode Shellcode Injector
um driver que usa sua liberdade no Kernel  para injetar shellcode de Ring 0 para Ring 3 (User-Mode) via manual mapping.
O driver é construído em C puro, resolvendo APIs dinamicamente e usando timers em background para aguardar o processo alvo. Ele não depende das rotinas padrões de carregamento do SO.
