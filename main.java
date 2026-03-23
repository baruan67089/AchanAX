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
