package org.kalaider.snmp;

import lombok.Data;
import lombok.extern.java.Log;
import net.percederberg.mibble.*;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.OptionHandlerFilter;
import org.kohsuke.args4j.spi.StringArrayOptionHandler;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Objects;
import java.util.logging.Level;
import java.util.stream.Stream;

@Log
public class Main {

    private enum Command {
        RESOLVE,
        GET
    }

    @Data
    private static final class Config {

        @Argument(metaVar = "command", required = true)
        private Command command;

        @Option(name = "-h", aliases = "--host")
        private String host = "localhost";

        @Option(name = "-p", aliases = "--port")
        private int port = 161;

        @Option(name = "-i", aliases = "--oid", forbids = "-s")
        private String oid;

        @Option(name = "-s", aliases = "--symbol", forbids = "-i")
        private String symbol;

        @Option(name = "-c", aliases = "--community")
        private String community = "public";

        @Option(name = "-v", aliases = "--snmp-version")
        private int version = SnmpConstants.version1;

        @Option(name = "-d", aliases = "--mibs-root-dir")
        private File mibsRootDir = new File(".");

        @Option(name = "-m", aliases = "--mibs", handler = StringArrayOptionHandler.class)
        private String[] mibs = new String[] {
                "SNMPv2-SMI",
                "SNMPv2-TC",
                "SNMPv2-MIB",
                "HOST-RESOURCES-MIB"
        };
    }

    private final Config config = new Config();
    private final MibLoader loader = new MibLoader();

    public static void main(String[] args) throws Exception {
        new Main().doMain(args);
    }

    private void doMain(String[] args) throws Exception {
        CmdLineParser parser = new CmdLineParser(config);

        try {
            parser.parseArgument(args);

            if (config.getSymbol() == null && config.getOid() == null) {
                throw new RuntimeException("Either OID or symbol name must be provided");
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.err.println("sys-3-snmp command [options...] arguments...");
            parser.printUsage(System.err);
            System.err.println();
            System.err.println("  Example: sys-3-snmp " + parser.printExample(OptionHandlerFilter.ALL));

            return;
        }

        System.out.println("Your configuration: " + config);

        loadMibs();

        switch (config.getCommand()) {
            case RESOLVE:
                resolve();
                break;
            case GET:
                get();
                break;
        }
    }

    private void loadMibs() {
        loader.addAllDirs(config.getMibsRootDir());
        Stream.of(config.getMibs()).forEach(s -> {
            try {
                loader.load(s);
            } catch (IOException e) {
                log.log(Level.SEVERE, "Unable to load file", e);
            } catch (MibLoaderException e) {
                log.log(Level.SEVERE, "Unable to load MIB", e);
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                e.getLog().printTo(new PrintStream(o));
                log.log(Level.SEVERE, o.toString());
            }
        });
    }

    private MibValueSymbol resolve() {
        if (config.getOid() != null) {
            MibValueSymbol symbol = loader.getRootOid().find(config.getOid()).getSymbol();
            log.info(symbol.toString());
            return symbol;
        } else {
            MibSymbol symbol = loader.getMibs().values().stream()
                    .map(m -> m.getSymbol(config.getSymbol()))
                    .filter(Objects::nonNull)
                    .findFirst().orElse(null);
            if (!(symbol instanceof MibValueSymbol)) symbol = null;
            log.info(Objects.toString(symbol));
            return (MibValueSymbol)symbol;
        }
    }

    private void get() throws Exception {
        TransportMapping transport = new DefaultUdpTransportMapping();
        transport.listen();

        // create Target Address object
        CommunityTarget comtarget = new CommunityTarget();
        comtarget.setCommunity(new OctetString(config.getCommunity()));
        comtarget.setVersion(config.getVersion());
        comtarget.setAddress(new UdpAddress(config.getHost() + "/" + config.getPort()));
        comtarget.setRetries(2);
        comtarget.setTimeout(1000);

        MibValueSymbol symbol = resolve();

        // create the PDU object
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(new OID(normalizeOid(symbol.getOid().toString()))));
        pdu.setType(PDU.GET);
        pdu.setRequestID(new Integer32(1));

        // create Snmp object for sending data to Agent
        Snmp snmp = new Snmp(transport);

        log.info("Sending Request to Agent...");
        ResponseEvent response = snmp.get(pdu, comtarget);

        // Process Agent Response
        if (response != null) {
            log.info("Got Response from Agent");
            PDU responsePDU = response.getResponse();

            if (responsePDU != null) {
                int errorStatus = responsePDU.getErrorStatus();
                int errorIndex = responsePDU.getErrorIndex();
                String errorStatusText = responsePDU.getErrorStatusText();

                if (errorStatus == PDU.noError) {
                    log.info("Snmp Get Response = " + responsePDU.getVariableBindings());
                } else {
                    log.severe("Error: Request Failed");
                    log.severe("Error Status = " + errorStatus);
                    log.severe("Error Index = " + errorIndex);
                    log.severe("Error Status Text = " + errorStatusText);
                }
            } else {
                log.severe("Error: Response PDU is null");
            }
        } else {
            log.severe("Error: Agent Timeout... ");
        }
        snmp.close();
    }

    private String normalizeOid(String oid) {
        if (!oid.endsWith(".0")) oid += ".0";
        return oid;
    }
}
