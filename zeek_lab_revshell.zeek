# Zeek script for Reverse Shell Network Detection Study (lab only)

export {
    redef enum Notice::Type += {
        Lab_Suspicious_Reverse_Shell
    };
}

event connection_state_remove(c: connection) {
    if ( c$id$orig_h == 192.168.56.20 &&
         c$id$resp_h == 192.168.56.10 &&
         c$id$resp_p > 1024/tcp &&
         c$duration > 60sec ) {

        NOTICE([$note=Lab_Suspicious_Reverse_Shell,
                $msg=fmt("LAB Suspicious long-lived high-port connection %s -> %s:%s (duration %.1f s)",
                         c$id$orig_h, c$id$resp_h, c$id$resp_p, c$duration)]);
    }
}

