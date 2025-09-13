export const metadata = {
  title: 'firewall-agent UI',
  description: 'Visualize Docker Swarm firewall topology',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, Noto Sans, sans-serif' }}>
        {children}
      </body>
    </html>
  );
}

