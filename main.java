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
