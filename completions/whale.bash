_whale() { COMPREPLY=( $(compgen -W 'up down status' -- "${COMP_WORDS[COMP_CWORD]}") ); }
complete -F _whale whale
