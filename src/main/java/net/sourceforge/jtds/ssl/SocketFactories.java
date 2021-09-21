// jTDS JDBC Driver for Microsoft SQL Server and Sybase
//Copyright (C) 2004 The jTDS Project
//
//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.
//
//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//Lesser General Public License for more details.
//
//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
//
package net.sourceforge.jtds.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import net.sourceforge.jtds.util.Logger;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Used for acquiring a socket factory when SSL is enabled.
 *
 * @author Rob Worsnop
 * @author Mike Hutchinson
 * @version $Id: SocketFactories.java,v 1.8.2.1 2009-07-23 15:32:51 ickzon Exp $
 */
public class SocketFactories {

    /**
     * KeyStore for composite Trust manager
     */
    private static KeyStore compositeKeyStore = null;

    /**
     * lock
     */
    private static final Object lock = new Object();

    /**
     * Returns a socket factory, the behavior of which will depend on the SSL
     * setting and whether or not the DB server supports SSL.
     *
     * @param ssl    the SSL setting
     * @param socket plain TCP/IP socket to wrap
     */
    public static SocketFactory getSocketFactory(String ssl, Socket socket) {
        return new TdsTlsSocketFactory(ssl, socket);
    }

    /**
     * create a key store using an external ca-certs file.
     * The file type should be BKS, not JKS.
     * Note : Android does not support JKS type.
     * <p>
     * Please have a look at about_cacerts.txt for detail on jtds-cacerts.bks.
     *
     * @return KeyStore
     */
    private static KeyStore getCompositeKeyStore() {
        synchronized (lock) {
            if (compositeKeyStore != null) {
                return compositeKeyStore;
            }
            try {
                compositeKeyStore = KeyStore.getInstance("BKS", "BC");
                InputStream is = SocketFactories.class.getResourceAsStream("jtds-cacerts.bks");
                compositeKeyStore.load(is, "changeit".toCharArray());
                return compositeKeyStore;
            } catch (Exception ex) {
                ex.printStackTrace();
                compositeKeyStore = null;
            }
            return compositeKeyStore;
        }
    }

    public static void setCompositeKeyStore(final KeyStore keyStore) {
        synchronized (lock) {
            if (keyStore != null) {
                compositeKeyStore = keyStore;
            }
        }
    }

    /**
     * The socket factory for creating sockets based on the SSL setting.
     */
    private static class TdsTlsSocketFactory extends SocketFactory {
        private static SSLSocketFactory factorySingleton;

        private final String ssl;
        private final Socket socket;

        /**
         * Constructs a TdsTlsSocketFactory.
         *
         * @param ssl    the SSL setting
         * @param socket the TCP/IP socket to wrap
         */
        public TdsTlsSocketFactory(String ssl, Socket socket) {
            this.ssl = ssl;
            this.socket = socket;
        }

        /**
         * Create the SSL socket.
         * <p/>
         * NB. This method will actually create a connected socket over the
         * TCP/IP network socket supplied via the constructor of this factory
         * class.
         */
        public Socket createSocket(String host, int port) throws IOException {
            try {
                SSLSocket sslSocket = (SSLSocket) enableTLSOnSocket(
                        getFactory().createSocket(new TdsTlsSocket(socket), host, port, true)
                );

                if (host != null && host.length() > 0) {
                    try {
                        // Enable SNI
                        BCSSLParameters bcsslParameters = new BCSSLParameters();
                        List<BCSNIServerName> hostNameList = new ArrayList<>();
                        hostNameList.add(new BCSNIHostName(host));
                        bcsslParameters.setServerNames(hostNameList);
                        BCSSLSocket bcsslSocket = (BCSSLSocket) sslSocket;
                        bcsslSocket.setParameters(bcsslParameters);
                    } catch (Exception ex) {
                        Logger.logException(ex);
                    }
                }

                //
                // See if connecting to local server.
                // getLocalHost() will normally return the address of a real
                // local network interface so we check that one and the loopback
                // address localhost/127.0.0.1
                //
                // XXX: Disable TLS resume altogether, because the cause of local
                // server failures is unknown and it also seems to sometiles occur
                // with remote servers.
                //
//            if (socket.getInetAddress().equals(InetAddress.getLocalHost()) ||
//                host.equalsIgnoreCase("localhost") || host.startsWith("127.")) {
                // Resume session causes failures with a local server
                // Invalidate the session to prevent resumes.
                sslSocket.startHandshake(); // Any IOException thrown here
                sslSocket.getSession().invalidate();
//                Logger.println("TLS Resume disabled");
//            }

                return sslSocket;
            } catch (Exception e) {
                Logger.logException(e);
                throw new IOException(e.getMessage());
            }
        }

        /*
         * (non-Javadoc)
         *
         * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int)
         */
        public Socket createSocket(InetAddress host, int port)
                throws IOException {
            return null;
        }

        /*
         * (non-Javadoc)
         *
         * @see javax.net.SocketFactory#createSocket(java.lang.String, int,
         *      java.net.InetAddress, int)
         */
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
            return null;
        }

        /*
         * (non-Javadoc)
         *
         * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int,
         *      java.net.InetAddress, int)
         */
        public Socket createSocket(InetAddress host, int port, InetAddress localHost, int localPort) throws IOException {
            return null;
        }

        /**
         * Returns an SSLSocketFactory whose behavior will depend on the SSL
         * setting.
         *
         * @return an <code>SSLSocketFactory</code>
         */
        private SSLSocketFactory getFactory() throws IOException {
            try {
                if (Ssl.SSL_AUTHENTICATE.equals(ssl)) {
                    // the default factory will produce a socket that authenticates
                    // the server using its certificate chain.
                    SSLContext context = SSLContext.getInstance("TLSv1.2", new BouncyCastleJsseProvider());
                    // Composite Trust Manager = default trust manager + trust manager with custom CA Certs
                    context.init(null, CompositeX509TrustManager.getTrustManagers(SocketFactories.getCompositeKeyStore()), null);
                    return context.getSocketFactory(); // always return a new instance
                } else {
                    if (factorySingleton == null) {
                        SSLContext context = SSLContext.getInstance("TLSv1.2", new BouncyCastleJsseProvider());
                        // Our custom factory will not authenticate the server.
                        context.init(null, getTrustManagersAcceptingAllCerts(), null);
                        factorySingleton = context.getSocketFactory();
                    }
                    return factorySingleton; // return a static instance
                }
            } catch (GeneralSecurityException e) {
                Logger.logException(e);
                throw new IOException(e.getMessage());
            }
        }

        private static TrustManager[] getTrustManagersAcceptingAllCerts() {
            X509TrustManager tm = new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkServerTrusted(X509Certificate[] chain, String x) {
                    // Dummy method
                }

                public void checkClientTrusted(X509Certificate[] chain, String x) {
                    // Dummy method
                }

            };

            return new X509TrustManager[]{tm};
        }

        private Socket enableTLSOnSocket(Socket socket) {
            if (socket instanceof SSLSocket) {
                ((SSLSocket) socket).setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"});
                ((SSLSocket) socket).setUseClientMode(true);
            }
            return socket;
        }
    }
}