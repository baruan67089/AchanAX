import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

/**
 * AchanAX — Nenek Boomer Claw helper (single-file Java app).
 *
 * Offline tools:
 * - generate a bytes32 seed
 * - compute commit seedHash = keccak256(seed)
 * - simulate reveal entropy + rollBps exactly like the Solidity contract
 *
 * Optional:
 * - provide contract roundSalt + winOddsBps to decide candidate (roll < winOddsBps)
 *
 * Notes:
 * - This tool intentionally avoids any on-chain side effects by default.
 */
public final class AchanAX {

    private static final int BPS_DENOM = 10_000;
    private static final SecureRandom RNG = new SecureRandom();

    // Mirrors Atunga.sol config bounds (for round-params simulation).
    private static final int ATG_MAX_FEE_BPS = 750;
    private static final int ATG_MIN_WIN_ODDS_BPS = 25;
    private static final int ATG_MAX_WIN_ODDS_BPS = 9_750;
    private static final long ATG_MIN_DEPOSIT_WEI = 500_000_000_000_000L; // 5e14
    private static final long ATG_MIN_COMMIT_SECS = 7L * 60L; // 7 minutes
    private static final long ATG_MAX_COMMIT_SECS = 70L * 60L; // 70 minutes
    private static final long ATG_MIN_REVEAL_SECS = 6L * 60L; // 6 minutes
    private static final long ATG_MAX_REVEAL_SECS = 65L * 60L; // 65 minutes
    private static final int ATG_HARD_ENTRY_CAP = 2048;

    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            printUsage();
            return;
        }

        String cmd = args[0].trim().toLowerCase(Locale.ROOT);
        try {
            switch (cmd) {
                case "gen-seed" -> cmdGenSeed();
                case "commit" -> cmdCommit(args);
                case "simulate" -> cmdSimulate(args);
                case "gen-salt" -> cmdGenSalt();
                case "gen-address" -> cmdGenAddress();
                case "eip55" -> cmdEip55(args);
                case "round-params" -> cmdRoundParams(args);
                default -> printUsage();
            }
        } catch (Exception e) {
            System.err.println("AchanAX error: " + e.getMessage());
            // Keep the tool quiet by default; stack traces can be noisy.
        }
    }

    private static void printUsage() {
        System.out.println("AchanAX commands:");
        System.out.println("  gen-seed");
        System.out.println("  commit --seed 0x<bytes32>");
        System.out.println("  simulate --seed 0x<bytes32> --player 0x<address> --roundId <uint> --seedHash 0x<bytes32> --roundSalt 0x<bytes32> --winOddsBps <uint>");
        System.out.println("  gen-salt");
        System.out.println("  gen-address");
        System.out.println("  eip55 --addr 0x<40hex>");
        System.out.println("  round-params --atgDomain 0x<bytes32> --roundId <uint> --prevBlockHash 0x<bytes32> --timestamp <uint64>");
        System.out.println();
        System.out.println("Example values not printed to avoid copy-paste mistakes.");
    }

    private static void cmdGenSeed() {
        byte[] seed = new byte[32];
        RNG.nextBytes(seed);
        String seedHex = "0x" + Hex.toHex(seed);
        String seedHashHex = "0x" + Hex.toHex(Keccak.keccak256(seed));
        System.out.println("seed=" + seedHex);
        System.out.println("seedHash=" + seedHashHex);
    }

    private static void cmdCommit(String[] args) {
        // commit --seed 0x...
        String seedHex = getArg(args, "--seed", true);
        byte[] seed = Hex.fromHex32(seedHex, "seed");
        byte[] seedHash = Keccak.keccak256(seed); // keccak256(abi.encodePacked(seed)) for bytes32 is keccak256(seed)
        System.out.println("seedHash=0x" + Hex.toHex(seedHash));
    }

    private static void cmdSimulate(String[] args) {
        String seedHex = getArg(args, "--seed", true);
        String playerHex = getArg(args, "--player", true);
        String roundIdStr = getArg(args, "--roundId", true);
        String seedHashHex = getArg(args, "--seedHash", true);
        String roundSaltHex = getArg(args, "--roundSalt", true);
        String winOddsBpsStr = getArg(args, "--winOddsBps", true);

        byte[] seed = Hex.fromHex32(seedHex, "seed");
        byte[] player = Hex.fromHex20(playerHex, "player");
        BigInteger roundId = new BigInteger(roundIdStr.trim());
        if (roundId.signum() < 0) throw new IllegalArgumentException("roundId must be non-negative");
        byte[] seedHash = Hex.fromHex32(seedHashHex, "seedHash");
        byte[] roundSalt = Hex.fromHex32(roundSaltHex, "roundSalt");
        int winOddsBps = new BigInteger(winOddsBpsStr.trim()).intValueExact();

        byte[] entropy = abiPackedEntropy(seed, player, roundId, seedHash, roundSalt);
        BigInteger entropyInt = new BigInteger(1, entropy);
        int rollBps = entropyInt.mod(BigInteger.valueOf(BPS_DENOM)).intValueExact();
        boolean candidate = rollBps < winOddsBps;

        System.out.println("rollBps=" + rollBps);
        System.out.println("candidate=" + candidate);
        System.out.println("entropy=0x" + Hex.toHex(entropy));
    }

    private static void cmdGenSalt() {
        byte[] salt = new byte[32];
        RNG.nextBytes(salt);
        String saltHex = "0x" + Hex.toHex(salt);
        System.out.println("roundSalt=" + saltHex);
    }

    private static void cmdGenAddress() {
        String addr = eip55Checksum(randomAddressLowercaseHex());
        System.out.println("address=" + addr);
    }

    private static void cmdEip55(String[] args) {
        String addr = getArg(args, "--addr", true);
        String lower = normalizeAddressLowercase(addr);
        String chk = eip55Checksum(lower);
        System.out.println("eip55=" + chk);
    }

    private static void cmdRoundParams(String[] args) {
        String atgDomainHex = getArg(args, "--atgDomain", true);
        String roundIdStr = getArg(args, "--roundId", true);
        String prevBlockHashHex = getArg(args, "--prevBlockHash", true);
        String timestampStr = getArg(args, "--timestamp", true);

        byte[] atgDomain = Hex.fromHex32(atgDomainHex, "atgDomain");
        long roundId = Long.parseLong(roundIdStr.trim());
        byte[] prevBlockHash = Hex.fromHex32(prevBlockHashHex, "prevBlockHash");
        long timestamp = Long.parseLong(timestampStr.trim());
        if (roundId < 0) throw new IllegalArgumentException("roundId must be >= 0");
        if (timestamp < 0) throw new IllegalArgumentException("timestamp must be >= 0");

        byte[] roundIdEnc = abiUint256To32Bytes(BigInteger.valueOf(roundId));
        byte[] tsEnc = abiUint256To32Bytes(BigInteger.valueOf(timestamp));

        // salt = keccak256(abi.encodePacked(ATG_DOMAIN, currentRoundId, blockhash(block.number - 1), block.timestamp))
        byte[] saltPacked = concat(atgDomain, roundIdEnc, prevBlockHash, tsEnc);
        byte[] salt = Keccak.keccak256(saltPacked);

        // commitLen
        byte[] commitLenHash = Keccak.keccak256(concat(salt, asciiBytes("COMMIT_LEN")));
        BigInteger commitLenV = new BigInteger(1, commitLenHash).mod(twoTo64());
        long commitLen = boundU64(commitLenV.longValue(), ATG_MIN_COMMIT_SECS, ATG_MAX_COMMIT_SECS);

        byte[] revealLenHash = Keccak.keccak256(concat(salt, asciiBytes("REVEAL_LEN")));
        BigInteger revealLenV = new BigInteger(1, revealLenHash).mod(twoTo64());
        long revealLen = boundU64(revealLenV.longValue(), ATG_MIN_REVEAL_SECS, ATG_MAX_REVEAL_SECS);

        // minDepositWei
        byte[] minDepositHash = Keccak.keccak256(concat(salt, asciiBytes("MIN_DEPOSIT")));
        BigInteger minDepositU256 = new BigInteger(1, minDepositHash);
        long minDepositWei = boundU256(minDepositU256, ATG_MIN_DEPOSIT_WEI, 5_000_000_000_000_000_000L);

        // feeBps
        byte[] feeHash = Keccak.keccak256(concat(salt, asciiBytes("FEE_BPS")));
        int feeBps = boundU16(modToInt(feeHash, ATG_MAX_FEE_BPS));
        if (feeBps == 0 || feeBps > ATG_MAX_FEE_BPS) feeBps = ATG_MAX_FEE_BPS;

        // winOddsBps
        byte[] winHash = Keccak.keccak256(concat(salt, asciiBytes("WIN_ODDS")));
        int winOddsBps = boundU16(modToInt(winHash, ATG_MAX_WIN_ODDS_BPS));
        if (winOddsBps < ATG_MIN_WIN_ODDS_BPS) winOddsBps = ATG_MIN_WIN_ODDS_BPS;

        // maxEntries
        byte[] maxEntriesHash = Keccak.keccak256(concat(salt, asciiBytes("MAX_ENTRIES")));
        int maxEntries = boundU32((modToInt(maxEntriesHash, 400) + 16), 16, ATG_HARD_ENTRY_CAP);

        long commitEndsAt = timestamp + commitLen;
        long revealEndsAt = commitEndsAt + revealLen;

        System.out.println("roundSalt=" + "0x" + Hex.toHex(salt));
        System.out.println("commitLen=" + commitLen + "s");
        System.out.println("revealLen=" + revealLen + "s");
        System.out.println("minDepositWei=" + minDepositWei);
        System.out.println("minDepositEth=" + (minDepositWei / 1e18));
        System.out.println("feeBps=" + feeBps);
        System.out.println("winOddsBps=" + winOddsBps);
        System.out.println("maxEntries=" + maxEntries);
        System.out.println("commitEndsAt=" + commitEndsAt + " (unix)");
        System.out.println("revealEndsAt=" + revealEndsAt + " (unix)");
    }

    private static void cmdComputeRoll(String[] args) {
        // compute-roll --seed 0x.. --player 0x.. --roundId <uint> --seedHash 0x.. --roundSalt 0x.. --winOddsBps <uint>
        String seedHex = getArg(args, "--seed", true);
        String playerHex = getArg(args, "--player", true);
        String roundIdStr = getArg(args, "--roundId", true);
        String seedHashHex = getArg(args, "--seedHash", true);
        String roundSaltHex = getArg(args, "--roundSalt", true);
        String winOddsBpsStr = getArg(args, "--winOddsBps", true);

        byte[] seed = Hex.fromHex32(seedHex, "seed");
        byte[] player = Hex.fromHex20(playerHex, "player");
        BigInteger roundId = new BigInteger(roundIdStr.trim());
        byte[] seedHash = Hex.fromHex32(seedHashHex, "seedHash");
        byte[] roundSalt = Hex.fromHex32(roundSaltHex, "roundSalt");
        int winOddsBps = new BigInteger(winOddsBpsStr.trim()).intValueExact();

        byte[] entropy = abiPackedEntropy(seed, player, roundId, seedHash, roundSalt);
        BigInteger entropyInt = new BigInteger(1, entropy);
        int rollBps = entropyInt.mod(BigInteger.valueOf(BPS_DENOM)).intValueExact();
        boolean candidate = rollBps < winOddsBps;
        System.out.println("rollBps=" + rollBps);
        System.out.println("candidate=" + candidate);
    }

    // -------------------------------------------------------------------------
    // Shared math + encoding helpers
    // -------------------------------------------------------------------------
    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            if (p == null) continue;
            total += p.length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            if (p == null) continue;
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    private static byte[] asciiBytes(String s) {
        if (s == null) return new byte[0];
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static BigInteger twoTo64() {
        return BigInteger.ONE.shiftLeft(64);
    }

    private static int modToInt(byte[] hash, int mod) {
        BigInteger x = new BigInteger(1, hash);
        return x.mod(BigInteger.valueOf(mod)).intValueExact();
    }

    private static long boundU64(long v, long minV, long maxV) {
        if (v < minV) return minV;
        if (v > maxV) return maxV;
        return v;
    }

    private static int boundU16(int v) {
        if (v <= 0) return 1;
        // keep within uint16
        if (v > 65535) return 65535;
        return v;
    }

    private static int boundU32(int v, int minV, int maxV) {
        if (v < minV) return minV;
        if (v > maxV) return maxV;
        return v;
    }

    private static long boundU256(BigInteger v, long minV, long maxV) {
        // v can be up to 2^256-1; we clamp to [minV, maxV] by comparing via BigInteger.
        if (v.compareTo(BigInteger.valueOf(minV)) < 0) return minV;
        if (v.compareTo(BigInteger.valueOf(maxV)) > 0) return maxV;
        return v.longValue();
    }

    private static byte[] abiUint256To32Bytes(BigInteger v) {
        return abiUint256(v);
    }

    // -------------------------------------------------------------------------
    // EIP-55 helpers (ASCII keccak of lowercase hex address)
    // -------------------------------------------------------------------------
    private static String randomAddressLowercaseHex() {
        byte[] addr = new byte[20];
        RNG.nextBytes(addr);
        return Hex.toHex(addr);
    }

    private static String normalizeAddressLowercase(String addr) {
        if (addr == null) throw new IllegalArgumentException("addr missing");
        String s = addr.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        if (s.length() != 40) throw new IllegalArgumentException("address must have 40 hex chars");
        for (int i = 0; i < 40; i++) {
            char c = s.charAt(i);
            if (Character.digit(c, 16) < 0) throw new IllegalArgumentException("invalid address hex");
        }
        return s.toLowerCase(Locale.ROOT);
    }

    private static String eip55Checksum(String addrLowerNoPrefix) {
        // addrLowerNoPrefix must be lowercase hex without 0x.
        String lower = normalizeAddressLowercase(addrLowerNoPrefix);
        byte[] hash = Keccak.keccak256(lower.getBytes(StandardCharsets.US_ASCII));
        String hashHex = Hex.toHex(hash);

        StringBuilder out = new StringBuilder("0x");
        for (int i = 0; i < 40; i++) {
            char c = lower.charAt(i);
            if (c >= 'a' && c <= 'f') {
                int nibble = Character.digit(hashHex.charAt(i), 16);
                if (nibble >= 8) out.append(Character.toUpperCase(c));
                else out.append(c);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    // Solidity (Atunga.sol) entropy:
    // keccak256(abi.encodePacked(seed, msg.sender, roundId, seedHash, roundSalt))
