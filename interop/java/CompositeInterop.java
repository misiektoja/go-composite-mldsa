// Checks composite ML-DSA artifacts made by the Go library with Bouncy Castle and produces the
// same artifacts with Bouncy Castle for the Go tests to check.
//
// Usage: java -cp <bcprov:bcpkix:bcutil> CompositeInterop.java <directory>
//
// <directory>/go/<algorithm> holds the Go artifacts. Every check prints one line starting with
// PASS or FAIL. Bouncy Castle writes its artifacts to <directory>/bc/<algorithm> and a signature
// made with the Go private key to <directory>/go/<algorithm>/bc-signature.bin.

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class CompositeInterop {
    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: CompositeInterop <directory>");
            System.exit(2);
        }
        Security.addProvider(new BouncyCastleProvider());
        Path base = Path.of(args[0]);
        List<Path> algorithms;
        try (Stream<Path> dirs = Files.list(base.resolve("go"))) {
            algorithms = dirs.filter(Files::isDirectory).sorted().toList();
        }
        for (Path dir : algorithms) {
            String alg = dir.getFileName().toString();
            checkGo(alg, dir);
            produce(alg, base.resolve("bc").resolve(alg), Files.readAllBytes(dir.resolve("message.bin")), Files.readAllBytes(dir.resolve("context.bin")));
        }
        System.exit(failures == 0 ? 0 : 1);
    }

    // Records the outcome of one named check and never lets an exception end the run.
    private static void check(String alg, String name, Check body) {
        try {
            if (body.run()) {
                System.out.println("PASS " + alg + " " + name);
            } else {
                failures++;
                System.out.println("FAIL " + alg + " " + name + ": signature is not valid");
            }
        } catch (Exception e) {
            failures++;
            System.out.println("FAIL " + alg + " " + name + ": " + e);
        }
    }

    private interface Check {
        boolean run() throws Exception;
    }

    // Verifies the certificates, revocation list, request, signatures and private key made by Go.
    private static void checkGo(String alg, Path dir) throws Exception {
        X509CertificateHolder root = new X509CertificateHolder(Files.readAllBytes(dir.resolve("root.der")));
        X509CertificateHolder leaf = new X509CertificateHolder(Files.readAllBytes(dir.resolve("leaf.der")));
        X509CertificateHolder ecLeaf = new X509CertificateHolder(Files.readAllBytes(dir.resolve("ecleaf.der")));
        ContentVerifierProvider rootVerifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(root);
        byte[] message = Files.readAllBytes(dir.resolve("message.bin"));
        byte[] context = Files.readAllBytes(dir.resolve("context.bin"));
        PublicKey leafKey = KeyFactory.getInstance(alg, "BC").generatePublic(new X509EncodedKeySpec(leaf.getSubjectPublicKeyInfo().getEncoded()));

        check(alg, "root-algorithm-identifier", () -> root.getSignatureAlgorithm().getAlgorithm().equals(root.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()) && root.getSignatureAlgorithm().getParameters() == null && root.getSubjectPublicKeyInfo().getAlgorithm().getParameters() == null);
        check(alg, "root-self-signature", () -> root.isSignatureValid(rootVerifier));
        check(alg, "composite-leaf-signature", () -> leaf.isSignatureValid(rootVerifier));
        check(alg, "ecdsa-leaf-signature", () -> ecLeaf.isSignatureValid(rootVerifier));
        check(alg, "crl-signature", () -> new X509CRLHolder(Files.readAllBytes(dir.resolve("crl.der"))).isSignatureValid(rootVerifier));
        check(alg, "csr-signature", () -> {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Files.readAllBytes(dir.resolve("csr.der")));
            return csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(csr.getSubjectPublicKeyInfo()));
        });
        check(alg, "raw-signature", () -> verify(alg, leafKey, message, null, Files.readAllBytes(dir.resolve("signature.bin"))));
        check(alg, "raw-signature-with-context", () -> verify(alg, leafKey, message, context, Files.readAllBytes(dir.resolve("context-signature.bin"))));
        check(alg, "raw-signature-wrong-context-rejected", () -> !verify(alg, leafKey, message, context, Files.readAllBytes(dir.resolve("signature.bin"))));
        check(alg, "pkcs8-import", () -> {
            PrivateKey key = KeyFactory.getInstance(alg, "BC").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(dir.resolve("leaf-key.p8"))));
            byte[] signature = sign(alg, key, message, null);
            Files.write(dir.resolve("bc-signature.bin"), signature);
            return verify(alg, leafKey, message, null, signature);
        });
    }

    // Produces a root, leaf, revocation list, request, private key and raw signatures.
    private static void produce(String alg, Path dir, byte[] message, byte[] context) throws Exception {
        Files.createDirectories(dir);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(alg, "BC");
        KeyPair rootKeys = generator.generateKeyPair();
        KeyPair leafKeys = generator.generateKeyPair();
        JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
        ContentSigner rootSigner = new JcaContentSignerBuilder(alg).setProvider("BC").build(rootKeys.getPrivate());
        Date now = new Date();
        Date later = new Date(now.getTime() + 3_600_000L);
        X500Name rootName = new X500Name("CN=Bouncy Castle Composite Root");

        X509CertificateHolder root = new JcaX509v3CertificateBuilder(rootName, BigInteger.ONE, now, later, rootName, rootKeys.getPublic())
            .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
            .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature))
            .addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(rootKeys.getPublic()))
            .build(rootSigner);
        X509CertificateHolder leaf = new JcaX509v3CertificateBuilder(rootName, BigInteger.TWO, now, later, new X500Name("CN=leaf.example.test"), leafKeys.getPublic())
            .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
            .addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(rootKeys.getPublic()))
            .build(new JcaContentSignerBuilder(alg).setProvider("BC").build(rootKeys.getPrivate()));
        X509v2CRLBuilder crl = new X509v2CRLBuilder(rootName, now);
        crl.setNextUpdate(later);
        crl.addCRLEntry(BigInteger.TWO, now, CRLReason.keyCompromise);
        crl.addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(rootKeys.getPublic()));
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=request"), leafKeys.getPublic())
            .build(new JcaContentSignerBuilder(alg).setProvider("BC").build(leafKeys.getPrivate()));

        Files.write(dir.resolve("root.der"), root.getEncoded());
        Files.write(dir.resolve("leaf.der"), leaf.getEncoded());
        Files.write(dir.resolve("crl.der"), crl.build(new JcaContentSignerBuilder(alg).setProvider("BC").build(rootKeys.getPrivate())).getEncoded());
        Files.write(dir.resolve("csr.der"), csr.getEncoded());
        Files.write(dir.resolve("root-key.p8"), rootKeys.getPrivate().getEncoded());
        Files.write(dir.resolve("signature.bin"), sign(alg, leafKeys.getPrivate(), message, null));
        Files.write(dir.resolve("context-signature.bin"), sign(alg, leafKeys.getPrivate(), message, context));
        System.out.println("PASS " + alg + " produce");
    }

    // Signs message with an optional application context.
    private static byte[] sign(String alg, PrivateKey key, byte[] message, byte[] context) throws Exception {
        Signature signature = Signature.getInstance(alg, "BC");
        signature.initSign(key);
        if (context != null) {
            signature.setParameter(new ContextParameterSpec(context));
        }
        signature.update(message);
        return signature.sign();
    }

    // Verifies a raw signature with an optional application context.
    private static boolean verify(String alg, PublicKey key, byte[] message, byte[] context, byte[] value) throws Exception {
        Signature signature = Signature.getInstance(alg, "BC");
        signature.initVerify(key);
        if (context != null) {
            signature.setParameter(new ContextParameterSpec(context));
        }
        signature.update(message);
        return signature.verify(value);
    }
}
