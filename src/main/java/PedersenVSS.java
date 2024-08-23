import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the Pedersen Verifiable Secret Sharing (VSS) scheme.
 * This implementation is based on the work by Pedersen (1991), which introduces
 * a non-interactive and information-theoretic secure verifiable secret sharing scheme.
 *
 * Reference:
 * Pedersen, Torben Pryds. "Non-interactive and information-theoretic secure verifiable secret sharing."
 * Annual International Cryptology Conference. Berlin, Heidelberg: Springer Berlin Heidelberg, 1991.
 * Available online: <a href="https://reaction.la/security/pedersons_secret_sharing.pdf">...</a>
 *
 * Author: shiyang
 */
public class PedersenVSS {

    /**
     * The pairing structure.
     * Public generator g.
     * Public generator h, derived independently of g.
     */
    private final Pairing pairing;
    private final Element g;
    private final Element h;

    /**
     * Constructs a PedersenVSS instance with the provided parameters.
     *
     * @param pairing The pairing structure used.
     * @param g       The public generator g.
     * @param h       The public generator h.
     * @throws IllegalArgumentException if g and h are equal.
     */
    public PedersenVSS(Pairing pairing, Element g, Element h) {
        if (g.isEqual(h)) {
            throw new IllegalArgumentException("Generators g and h must be different.");
        }
        this.pairing = pairing;
        this.g = g;
        this.h = h;
    }

    /**
     * Represents a share of the secret in the VSS scheme.
     *
     * @param index      The index of the share.
     * @param value1     The share value f(x).
     * @param value2     The share value g(x).
     * @param commitment The commitment corresponding to the share.
     */
    public record Share(int index, Element value1, Element value2, List<Element> commitment) {
    }

    /**
     * Distributes the secret and generates commitments for verifiable secret sharing.
     *
     * @param secret The secret to be shared. It must be a non-zero element.
     * @param t      The threshold t, representing the minimum number of shares required to reconstruct the secret.
     * @param n      The total number of participants.
     * @return A list of shares, each containing the full list of public commitments.
     * @throws IllegalArgumentException if t > n or secret is zero.
     */
    public List<Share> shareSecret(Element secret, int t, int n) {
        if (t > n) {
            throw new IllegalArgumentException("Threshold t cannot be greater than the total number of participants n.");
        }
        if (secret.isZero()) {
            throw new IllegalArgumentException("Secret must be a non-zero element.");
        }

        // Generate coefficients for f(x) and g(x), where f(0) = secret, g(0) = random value.
        List<Element> fCoefficients = new ArrayList<>();
        List<Element> gCoefficients = new ArrayList<>();

        // Field Zr (representing the finite field of the pairing structure).
        Field Zr = pairing.getZr();

        // Set f(0) = secret.
        fCoefficients.add(secret);
        // Set g(0) to a random value.
        gCoefficients.add(Zr.newRandomElement());

        // Generate other random coefficients for f(x) and g(x).
        for (int i = 1; i < t; i++) {
            fCoefficients.add(Zr.newRandomElement());
            gCoefficients.add(Zr.newRandomElement());
        }

        // Generate commitments C_i = g^f_i * h^g_i for each coefficient.
        List<Element> commitments = new ArrayList<>();
        for (int i = 0; i < t; i++) {
            Element commitment = g.duplicate().powZn(fCoefficients.get(i))
                    .add(h.duplicate().powZn(gCoefficients.get(i)));
            commitments.add(commitment);
        }

        // Generate shares for each participant.
        List<Share> shares = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            BigInteger x = BigInteger.valueOf(i);

            // Calculate f(x) and g(x).
            Element f_x = evaluatePolynomial(fCoefficients, x);
            Element g_x = evaluatePolynomial(gCoefficients, x);

            shares.add(new Share(i, f_x, g_x, commitments));
        }

        return shares;
    }

    /**
     * Reconstructs the secret from the provided shares using Lagrange interpolation.
     * <p>
     * The Lagrange interpolation formula is given by:
     * <p>
     * f(0) = Σ (f(x_i) * λ_i)
     * <p>
     * where λ_i is the Lagrange basis polynomial for the i-th share:
     * <p>
     * λ_i = Π (x_j / (x_j - x_i)) for all j ≠ i
     *
     * @param shares The list of shares used to reconstruct the secret. This list must contain at least
     *               t valid shares, where t is the threshold defined in the secret sharing scheme.
     *               Each share includes the value f(x_i) and its corresponding index x_i.
     * @param t      The threshold value representing the minimum number of shares required to reconstruct the secret.
     * @param n      The total number of participants.
     * @return The reconstructed secret as an Element, which is f(0), the value of the polynomial
     * evaluated at x = 0 (the original secret).
     * @throws IllegalArgumentException if the number of shares provided is less than the threshold t.
     */
    public Element reconstruct(List<Share> shares, int t, int n) {
        // Check that the number of shares is at least t, as required for reconstruction
        if (shares.size() < t) {
            throw new IllegalArgumentException("Not enough shares to reconstruct the secret. " +
                    "At least " + t + " shares are required.");
        }

        // Initialize the result (the reconstructed secret) to zero in the field Zr
        Element secret = pairing.getZr().newZeroElement();

        // Lagrange interpolation to calculate f(0)
        for (int i = 0; i < shares.size(); i++) {
            // Initialize the Lagrange basis polynomial λ_i to one
            Element lambda_i = pairing.getZr().newOneElement();
            BigInteger xi = BigInteger.valueOf(shares.get(i).index());

            // Compute the Lagrange basis polynomial λ_i for the i-th share
            for (int j = 0; j < shares.size(); j++) {
                if (i != j) {
                    BigInteger xj = BigInteger.valueOf(shares.get(j).index());

                    // λ_i *= (0 - x_j) / (x_i - x_j)

                    // 0 - x_j
                    Element numerator = pairing.getZr().newElement(xj.negate());
                    // (x_i - x_j)^(-1)
                    Element denominator = pairing.getZr().newElement(xi.subtract(xj)).invert();
                    // λ_i *= (numerator / denominator)
                    lambda_i = lambda_i.mul(numerator.mul(denominator));
                }
            }

            // Add the contribution of this share to the secret: f(x_i) * λ_i

            // f(x_i) is the share's value
            Element f_xi = shares.get(i).value1();
            // secret += f(x_i) * λ_i
            secret = secret.add(f_xi.mul(lambda_i));
        }

        // Return the reconstructed secret f(0)
        return secret;
    }

    /**
     * Verifies whether a given share is valid using commitments.
     *
     * @param share The share to be verified.
     * @return true if the share is valid, false otherwise.
     */
    public boolean verifyShare(Share share) {
        // Left-hand side of the verification equation: g^(f_x) * h^(g_x).
        Element lhs = g.duplicate().powZn(share.value1()).add(h.duplicate().powZn(share.value2()));
        // Right-hand side of the verification equation.
        Element rhs = pairing.getG1().newZeroElement();

        // Compute the right-hand side using commitments.
        BigInteger index = BigInteger.valueOf(share.index());
        for (int i = 0; i < share.commitment().size(); i++) {
            Element exponent = pairing.getZr().newElement(index.pow(i));
            rhs = rhs.add(share.commitment().get(i).duplicate().powZn(exponent));
        }

        // Verify if g^share_value equals the product of commitments.
        return lhs.isEqual(rhs);
    }

    /**
     * Evaluates a polynomial at a given point x using Horner's method.
     *
     * @param coefficients The list of coefficients of the polynomial.
     * @param x            The point at which the polynomial is to be evaluated.
     * @return The polynomial evaluated at the point x.
     */
    private Element evaluatePolynomial(List<Element> coefficients, BigInteger x) {
        Element result = pairing.getZr().newZeroElement();
        Element power = pairing.getZr().newOneElement();

        // Apply Horner's method to evaluate the polynomial.
        for (Element coefficient : coefficients) {
            result = result.add(coefficient.duplicate().mul(power));
            power = power.duplicate().mul(pairing.getZr().newElement(x));
        }

        return result;
    }

    public static void main(String[] args) {

        // Initialize pairing parameters.
        PairingParameters params = PairingFactory.getPairingParameters("a.properties");
        Pairing pairing = PairingFactory.getPairing(params);

        // Get the G1 group (elliptic curve group).
        Field<Element> G1 = pairing.getG1();

        // Generate two different generators g and h in G1.
        Element g = G1.newRandomElement().getImmutable();
        Element h;
        do {
            // Ensure g and h are different.
            h = G1.newRandomElement().getImmutable();
        } while (g.isEqual(h));

        // Create an instance of PedersenVSS with the provided parameters.
        PedersenVSS vss = new PedersenVSS(pairing, g, h);

        // Generate a random non-zero secret in Zr.
        Field Zr = pairing.getZr();
        Element secret;
        do {
            // If secret is zero, regenerate it.
            secret = Zr.newRandomElement();
        } while (secret.isZero());

        // Minimum number of shares needed to reconstruct the secret.
        int t = 3;
        // Total number of participants.
        int n = 5;

        // Distribute the secret and generate shares.
        List<Share> shares = vss.shareSecret(secret, t, n);

        // Print the values of g and h.
        System.out.println("Generator g in G1: " + g);
        System.out.println("Generator h in G1: " + h);

        // Verify the validity of each share.
        for (Share share : shares) {
            boolean isValid = vss.verifyShare(share);
            System.out.println("Share Index: " + share.index());
            System.out.println("Value1 (f_x): " + share.value1());
            System.out.println("Value2 (g_x): " + share.value2());
            System.out.println("Commitment: " + share.commitment());
            System.out.println("Validation Result: " + (isValid ? "valid" : "invalid"));
            System.out.println("---------------------------");
        }

        // Select the first t shares for secret reconstruction.
        List<Share> selectedShares = shares.subList(0, t);

        // Reconstruct the secret using the selected shares.
        Element reconstructedSecret = vss.reconstruct(selectedShares, 3, 5);

        System.out.println("Original Secret: " + secret);
        System.out.println("Reconstructed Secret: " + reconstructedSecret);

        // Compare the original secret and reconstructed secret.
        if (secret.isEqual(reconstructedSecret)) {
            System.out.println("Secret reconstruction: success");
        } else {
            System.out.println("Secret reconstruction: failure");
        }
    }
}
