// 
// Decompiled by Procyon v0.5.36
// 

package com.myfirstplugin;

public class BlockyCore
{
    public String sqlHost;
    public String sqlUser;
    public String sqlPass;
    
    public BlockyCore() {
        this.sqlHost = "localhost";
        this.sqlUser = "root";
        this.sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
    }
    
    public void onServerStart() {
    }
    
    public void onServerStop() {
    }
    
    public void onPlayerJoin() {
        this.sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
    }
    
    public void sendMessage(final String username, final String message) {
    }
}
