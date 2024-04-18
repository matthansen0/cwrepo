checkConnections(){
    {
    # ss -plunt
    echo "- ss plunt" 
    echo "\`\`\`bash" 
    ss -plunt 
    echo "\`\`\`" 

    # ss -punt
    echo "- ss punt" 
    echo "\`\`\`bash" 
    ss -punt 
    echo "\`\`\`" 

    # ss -p -f link
    echo "- ss -p -f link" 
    echo "\`\`\`bash" 
    ss -p -f link
    echo "\`\`\`" 

    # ss -p -f vsock
    echo "- ss -p -f vsock" 
    echo "\`\`\`bash" 
    ss -p -f vsock
    echo "\`\`\`" 

    # ss -p -f xdp
    echo "- ss -p -f xdp" 
    echo "\`\`\`bash" 
    ss -p -f xdp
    echo "\`\`\`" 
    } > /quarantine/connections
}