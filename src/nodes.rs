use std::process::{Command, Stdio};
use std::io::{self, BufRead, Write};
use tokio;


// This function gets all the mac addresses from the connected nodes.
// It simulates the following commands.
// 
// wingchen@raspberrypi:~ $ bridge fdb show | grep "enx5c628b686485" | grep "master br0"
// d8:3a:dd:00:1c:5f dev enx5c628b686485 master br0 
// d8:bb:c1:0a:68:03 dev enx5c628b686485 master br0 
// 9c:76:0e:32:6a:ad dev enx5c628b686485 master br0 
// 5c:62:8b:68:64:85 dev enx5c628b686485 master br0 permanent
async fn get_mac_addresses(interface: &str) -> io::Result<Vec<String>> {
    let command_output = Command::new("bridge")
        .arg("fdb")
        .arg("show")
        .stdout(Stdio::piped())
        .spawn()?
        .stdout
        .ok_or(io::Error::new(io::ErrorKind::Other, "Failed to capture stdout"))?;

    let grep_output = Command::new("grep")
        .arg(interface)
        .arg("-e")
        .arg("master tonleh_br0")
        .stdin(Stdio::from(command_output))
        .output()?;

    if !grep_output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to execute grep command",
        ));
    }

    let grep_result = String::from_utf8_lossy(&grep_output.stdout);

    let mac_addresses: Vec<String> = grep_result
        .lines()
        .filter_map(|line| {
            if !line.contains("permanent") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    Some(parts[0].to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    Ok(mac_addresses)
}

// This function makes sure that all the http requests goes through tonleh proxy server.
// It simulates the following commands:
// 
//  # ebtables rules for HTTP (port 80)
//  ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-dport 80 -i eth0 -s ! $mac_address -j redirect --redirect-target DROP
//  ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-sport 80 -o eth0 -d ! $mac_address -j redirect --redirect-target DROP

//  # ebtables rules for HTTPS (port 443)
//  ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-dport 443 -i eth0 -s ! $mac_address -j redirect --redirect-target DROP
//  ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-sport 443 -o eth0 -d ! $mac_address -j redirect --redirect-target DROP

//  # iptables rules for HTTP (port 80)
//  iptables -t mangle -A PREROUTING -i eth1 -p tcp -m tcp --dport 80 -s $mac_address -j TPROXY --on-ip 0.0.0.0 --on-port 8080 --tproxy-mark 1/1
//  iptables -t mangle -A PREROUTING -i eth0 -p tcp -m tcp --sport 80 -s $mac_address -j MARK --set-mark 1/1

//  # iptables rules for HTTPS (port 443)
//  iptables -t mangle -A PREROUTING -i eth1 -p tcp -m tcp --dport 443 -s $mac_address -j TPROXY --on-ip 0.0.0.0 --on-port 8080 --tproxy-mark 1/1
//  iptables -t mangle -A PREROUTING -i eth0 -p tcp -m tcp --sport 443 -s $mac_address -j MARK --set-mark 1/1
fn add_node_into_whitelist(mac_address: &str) -> io::Result<()> {
    // Define ebtables and iptables rules for HTTP (port 80)
    let ebtables_http_cmd1 = format!(
        "ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-dport 80 -i eth0 -s ! {} -j redirect --redirect-target DROP",
        mac_address
    );

    let ebtables_http_cmd2 = format!(
        "ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-sport 80 -o eth0 -d ! {} -j redirect --redirect-target DROP",
        mac_address
    );

    let iptables_http_cmd1 = format!(
        "iptables -t mangle -A PREROUTING -i eth1 -p tcp -m tcp --dport 80 -s {} -j TPROXY --on-ip 0.0.0.0 --on-port 8080 --tproxy-mark 1/1",
        mac_address
    );

    let iptables_http_cmd2 = format!(
        "iptables -t mangle -A PREROUTING -i eth0 -p tcp -m tcp --sport 80 -s {} -j MARK --set-mark 1/1",
        mac_address
    );

    // Define ebtables and iptables rules for HTTPS (port 443)
    let ebtables_https_cmd1 = format!(
        "ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-dport 443 -i eth0 -s ! {} -j redirect --redirect-target DROP",
        mac_address
    );

    let ebtables_https_cmd2 = format!(
        "ebtables -t broute -A BROUTING -p IPv4 --ip-proto tcp --ip-sport 443 -o eth0 -d ! {} -j redirect --redirect-target DROP",
        mac_address
    );

    let iptables_https_cmd1 = format!(
        "iptables -t mangle -A PREROUTING -i eth1 -p tcp -m tcp --dport 443 -s {} -j TPROXY --on-ip 0.0.0.0 --on-port 8080 --tproxy-mark 1/1",
        mac_address
    );

    let iptables_https_cmd2 = format!(
        "iptables -t mangle -A PREROUTING -i eth0 -p tcp -m tcp --sport 443 -s {} -j MARK --set-mark 1/1",
        mac_address
    );

    // Execute the commands for HTTP
    let status1 = Command::new("sh")
        .arg("-c")
        .arg(&ebtables_http_cmd1)
        .status()?;
    
    let status2 = Command::new("sh")
        .arg("-c")
        .arg(&ebtables_http_cmd2)
        .status()?;
    
    let status3 = Command::new("sh")
        .arg("-c")
        .arg(&iptables_http_cmd1)
        .status()?;
    
    let status4 = Command::new("sh")
        .arg("-c")
        .arg(&iptables_http_cmd2)
        .status()?;
    
    // Execute the commands for HTTPS
    let status5 = Command::new("sh")
        .arg("-c")
        .arg(&ebtables_https_cmd1)
        .status()?;
    
    let status6 = Command::new("sh")
        .arg("-c")
        .arg(&ebtables_https_cmd2)
        .status()?;
    
    let status7 = Command::new("sh")
        .arg("-c")
        .arg(&iptables_https_cmd1)
        .status()?;
    
    let status8 = Command::new("sh")
        .arg("-c")
        .arg(&iptables_https_cmd2)
        .status()?;

    // Check if any of the commands failed
    if status1.success() && status2.success() && status3.success() && status4.success()
        && status5.success() && status6.success() && status7.success() && status8.success()
    {
        println!("Commands executed successfully.");
    } else {
        eprintln!("Error: One or more commands failed to execute.");
    }

    Ok(())
}

// This function removes the entire whitelist.
// At the moment, the way to modify the whitelist is to wipe out the old one,
// and add each whitelisted mac address in as soon as there is any update.
// 
// This design prevents the syncing problem. It flashes the ebtables and iptables
// rules each time when we need to.
async fn wipe_white_list(mac_address: &str) -> io::Result<()> {
    // Remove all ebtables rules for HTTP and HTTPS
    let ebtables_undo_cmd = "ebtables -t broute -F BROUTING";
    let status1 = Command::new("sh")
        .arg("-c")
        .arg(ebtables_undo_cmd)
        .status()?;
    
    // Remove all iptables rules for HTTP and HTTPS
    let iptables_undo_cmd = "iptables -t mangle -F PREROUTING";
    let status2 = Command::new("sh")
        .arg("-c")
        .arg(iptables_undo_cmd)
        .status()?;
    
    // Check if any of the commands failed
    if status1.success() && status2.success() {
        println!("All rules undone successfully.");
    } else {
        eprintln!("Error: One or more commands failed to execute.");
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_mac_addresses() {
        // Define test cases with known input and expected output
        let test_cases = vec![
            ("enx5c628b686485", vec!["d8:3a:dd:00:1c:5f", "d8:bb:c1:0a:68:03"]),
            // Add more test cases as needed
        ];

        for (interface, expected) in test_cases {
            let result = get_mac_addresses(interface).await.unwrap();
            assert_eq!(result, expected);
        }
    }
}
