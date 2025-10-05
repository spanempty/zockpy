rule ransomware {
    strings:
        $encrypt = "encrypt"
        $decrypt = "decrypt"
        $bitcoin = "bitcoin"
        $wallet = "wallet"
        $locked = ".locked"
        $encrypted = ".encrypted"
    condition:
        any of them
}
