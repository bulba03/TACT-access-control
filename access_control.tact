import "@stdlib/deploy";
import "@stdlib/ownable";
trait AccessControl with Ownable {
    virtual const DEFAULT_ADMIN_ROLE: Int = sha256("ADMIN_ROLE");
    owner: Address;
    roles: map<Address, RoleData>; 

    receive(msg: SetRole) {
        self.has_role(context().sender, self.DEFAULT_ADMIN_ROLE);
        self.set_role(msg.address, sha256(msg.role));
    }

    receive(msg: RevokeRole) {
        self.revoke_role(msg.address);
    }

    fun set_role(addr: Address, role: Int) {
        let record: RoleData? = self.roles.get(addr);
        if(record != null) {
            let rec: RoleData = (record!!);
            rec.roles.set(role, true);
            self.roles.set(addr, rec);
        }
        else {
            let rec: RoleData = RoleData {
                roles: emptyMap()
            };
            rec.roles.set(role, true);
            self.roles.set(addr, rec);
        }
        
    }

    fun has_role(addr: Address, needed: Int) {
        let data: RoleData? = self.roles.get(context().sender);
        require(data != null, "Role Not Set");
        let binding: RoleData = data!!;
        let hasRole: Bool? = binding.roles.get(needed);
        require(hasRole != null, "Wrong role");
        let bind2: Bool = hasRole!!;
        require(bind2 == true, "Wrong role");
    }

    fun revoke_role(addr: Address) {
        self.has_role(context().sender, self.DEFAULT_ADMIN_ROLE);
        self.roles.set(addr, null);
    }
    
}

struct RoleData {
    roles: map<Int, Bool>;
}
message SetRole {
    address: Address;
    role: String;
}

message RevokeRole {
    address: Address;
}
