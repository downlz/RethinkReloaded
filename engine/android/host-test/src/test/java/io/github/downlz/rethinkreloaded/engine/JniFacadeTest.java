// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package io.github.downlz.rethinkreloaded.engine;

import static org.junit.Assert.*;

import com.celzero.firestack.backend.Backend;
import com.celzero.firestack.backend.DNSOpts;
import com.celzero.firestack.backend.IpTree;
import com.celzero.firestack.backend.RadixTree;
import com.celzero.firestack.backend.WgKey;
import com.celzero.firestack.intra.Intra;
import com.celzero.firestack.intra.Mark;
import com.celzero.firestack.settings.Settings;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Test;

/** Exercises the Rust libgojni through the unmodified gobind Java facade. */
public class JniFacadeTest {

    @Test
    public void buildIdentifiesRustEngine() {
        assertTrue(Intra.build(false).startsWith("rethinkreloaded-rust/"));
        assertTrue(Intra.build(true).contains("natives="));
    }

    @Test
    public void radixTree() {
        RadixTree t = Backend.newRadixTree();
        assertTrue(t.add("example.com"));
        assertFalse(t.add("example.com"));
        t.set(".example.org", "wild");
        assertEquals("wild", t.getAny("a.b.example.org"));
        assertEquals("", t.getAny("example.net")); // Go returns "", never null
        assertTrue(t.hasAny("x.example.org"));
        assertEquals(2, t.len());
        assertEquals(1, t.delAll(".example.org"));
        t.clear();
        assertEquals(0, t.len());
    }

    @Test
    public void ipTreeAndGoErrors() throws Exception {
        IpTree t = Backend.newIpTree();
        t.add("10.0.0.0/8", "p1");
        t.add("10.1.0.0/16", "p2");
        assertEquals("10.0.0.0/8,10.1.0.0/16", t.routes("10.1.2.3"));
        assertEquals("10.1.0.0/16@p2", t.getAny("10.1.2.3:443"));
        assertEquals("10.0.0.0/8@p1|10.1.0.0/16@p2", t.getAll("10.1.2.3"));
        assertTrue(t.hasAny("10.200.0.1"));
        assertEquals(2, t.len());
        try {
            t.get("not-an-ip");
            fail("expected an exception");
        } catch (Exception e) {
            // gobind surfaces Go errors as go.Universe$proxyerror; the Rust engine must do the same
            assertEquals("go.Universe$proxyerror", e.getClass().getName());
            assertTrue(e.getMessage(), e.getMessage().contains("ip2cidr"));
        }
        assertEquals("", t.routes("not-an-ip")); // non-throwing methods return Go zero values
        assertEquals(-1, t.escLike("not-an-ip", "x"));
    }

    @Test
    public void structsHaveGoZeroValuesAndSetters() {
        Mark m = new Mark();
        assertEquals("", m.getUID());
        m.setUID("10123");
        m.setPIDCSV("Base,Exit");
        assertEquals("10123", m.getUID());
        assertEquals("Base,Exit", m.getPIDCSV());
        Mark n = new Mark();
        n.setUID("10123");
        n.setPIDCSV("Base,Exit");
        assertEquals(m, n); // generated equals() reads fields through the natives

        DNSOpts o = new DNSOpts();
        o.setNOBLOCK(true);
        o.setIPCSV("1.1.1.1");
        assertTrue(o.getNOBLOCK());
        assertEquals("1.1.1.1", o.getIPCSV());
    }

    @Test
    public void wireguardKeys() throws Exception {
        // RFC 7748 6.1 (Alice): private key -> public key
        WgKey sk = Backend.newWgPrivateKeyOf("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=");
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", sk.mult().hex());
        WgKey gen = Backend.newWgPrivateKey();
        assertFalse(gen.isZero());
        assertEquals(44, gen.base64().length());
        try {
            Backend.newWgPrivateKeyOf("AAAA");
            fail("expected an exception");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("32 bytes"));
        }
    }

    @Test
    public void settings() {
        assertTrue(Settings.setDialerOpts(Settings.SplitDesync, Settings.RetryNever, 4096, 10, true));
        assertFalse(Settings.setDialerOpts(99, 99, 4096, 10, true));
        Settings.setAutoMode(Settings.AutoModeRemote);
        assertEquals(Settings.AutoModeRemote, Settings.setAutoMode(Settings.AutoModeLocal));
        assertEquals("dns ip 1", Settings.mode2String("dns", Settings.DNSModeIP));
        assertEquals("46", Settings.l3(Settings.Ns46));
    }

    @Test
    public void unimplementedAndRpnStubsThrowGoErrors() {
        try {
            Intra.addDNSCryptRelay(null, "sdns://x"); // DNSCrypt is a Phase 3 native: still a stub
            fail("expected an exception");
        } catch (Exception e) {
            assertEquals("go.Universe$proxyerror", e.getClass().getName());
            assertTrue(e.getMessage(), e.getMessage().contains("unimplemented"));
        }
        try {
            Intra.connect(-1, 1500, 1500, "", "", null, null); // implemented: rejects a nil bridge
            fail("expected an exception");
        } catch (Exception e) {
            assertEquals("go.Universe$proxyerror", e.getClass().getName());
            assertTrue(e.getMessage(), e.getMessage().contains("nil bridge"));
        }
        try {
            Backend.newPipKeyStateFrom("x");
            fail("expected an exception");
        } catch (Exception e) {
            assertTrue(e.getMessage(), e.getMessage().contains("rpn: unsupported"));
        }
    }

    @Test
    public void garbageCollectedProxiesReleaseRefnums() throws Exception {
        int before = liveRefs();
        for (int i = 0; i < 10_000; i++) {
            new Mark().setUID("x"); // each allocates a Rust-side struct behind a refnum
        }
        int peak = liveRefs();
        assertTrue("refnums allocated: " + before + " -> " + peak, peak >= before + 1000 || peak > 0);
        long deadline = System.currentTimeMillis() + 15_000;
        while (liveRefs() > before + 500 && System.currentTimeMillis() < deadline) {
            System.gc(); // phantom refs -> Seq.GoRefQueue -> Seq.destroyRef (Rust)
            Thread.sleep(50);
        }
        assertTrue("refnums not released: " + liveRefs(), liveRefs() <= before + 500);
    }

    private static int liveRefs() {
        Matcher m = Pattern.compile("refs=(\\d+)").matcher(Intra.build(true));
        assertTrue(m.find());
        return Integer.parseInt(m.group(1));
    }
}
