rule crypto_miner {
    strings:
        $xmrig = "xmrig"
        $cryptonight = "cryptonight"
        $minerd = "minerd"
        $cpuminer = "cpuminer"
    condition:
        any of them
}
