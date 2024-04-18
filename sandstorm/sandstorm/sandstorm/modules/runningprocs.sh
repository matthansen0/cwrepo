runningProcs(){
    {
    echo "- ps fux" 
    echo "\`\`\`bash" 
    ps -fux 
    echo "\`\`\`" 

    echo "- pstree" 
    echo "\`\`\`bash" 
    pstree
    echo "\`\`\`" 
    } > /quarantine/running-programs
}