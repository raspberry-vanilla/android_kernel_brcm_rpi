// SPDX-License-Identifier: GPL-2.0
/*
 * SPDX-FileCopyrightText: Copyright (c) 2018-2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <linux/console.h>
#include <linux/io.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/serial.h>
#include <linux/serial_core.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>

#define TCU_MBOX_BYTE(i, x)			((x) << (i * 8))
#define TCU_MBOX_BYTE_V(x, i)			(((x) >> (i * 8)) & 0xff)
#define TCU_MBOX_NUM_BYTES(x)			((x) << 24)
#define TCU_MBOX_NUM_BYTES_V(x)			(((x) >> 24) & 0x3)
#define TCU_MBOX_NUM_BYTES_MASK			TCU_MBOX_NUM_BYTES(0x3)
#define TCU_MBOX_INTR_TRIG_BIT			BIT(31)

static u32 tegra_tcu_early_update_mbox(u8 __iomem *addr, u32 mbox_val, char c)
{
	unsigned int bytes = TCU_MBOX_NUM_BYTES_V(mbox_val);
	unsigned char uc = (unsigned char)c;

	mbox_val |= TCU_MBOX_INTR_TRIG_BIT;
	mbox_val |= TCU_MBOX_BYTE(bytes, uc);
	bytes++;
	mbox_val = (mbox_val & ~TCU_MBOX_NUM_BYTES_MASK) |
		TCU_MBOX_NUM_BYTES(bytes);

	if (bytes == 3) {
		/* Send current packet to tcu driver*/
		while (readl(addr) & TCU_MBOX_INTR_TRIG_BIT)
			cpu_relax();
		writel(mbox_val, addr);
		mbox_val = TCU_MBOX_INTR_TRIG_BIT;
	}

	return mbox_val;
}

/*
 * This function splits the string to be printed (const char *s) into multiple
 * packets. Each packet contains a max of 3 characters. Packets are sent to the
 * combined UART server for printing. Communication with TCU is done
 * through mailbox registers which can generate interrupts for TCU.
 */
static void __init tegra_tcu_early_write(struct console *console,
			const char *s, unsigned int count)
{
	struct earlycon_device *device = console->data;
	u8 __iomem *addr = device->port.membase;
	u32 mbox_val = TCU_MBOX_INTR_TRIG_BIT;
	unsigned int i;

	/* Loop for processing each 3 char packet */
	for (i = 0; i < count; i++) {
		if (s[i] == '\n')
			mbox_val = tegra_tcu_early_update_mbox(addr, mbox_val, '\r');
		mbox_val = tegra_tcu_early_update_mbox(addr, mbox_val, s[i]);
	}

	if (TCU_MBOX_NUM_BYTES_V(mbox_val)) {
		while (readl(addr) & TCU_MBOX_INTR_TRIG_BIT)
			cpu_relax();
		writel(mbox_val, addr);
	}
}

static int __init tegra_tcu_early_setup(struct earlycon_device *device,
						const char *options)
{
	if (!(device->port.membase))
		return -ENODEV;

	device->con->write = tegra_tcu_early_write;

	return 0;
}

EARLYCON_DECLARE(tegra_tcu, tegra_tcu_early_setup);

struct tegra_tcu {
	struct uart_driver driver;
#if IS_ENABLED(CONFIG_SERIAL_TEGRA_TCU_CONSOLE)
	struct console console;
#endif
	struct uart_port port;

	struct mbox_client tx_client, rx_client;
	struct mbox_chan *tx, *rx;
};

static unsigned int tegra_tcu_uart_tx_empty(struct uart_port *port)
{
	return TIOCSER_TEMT;
}

static void tegra_tcu_uart_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
}

static unsigned int tegra_tcu_uart_get_mctrl(struct uart_port *port)
{
	return 0;
}

static void tegra_tcu_uart_stop_tx(struct uart_port *port)
{
}

static void tegra_tcu_write_one(struct tegra_tcu *tcu, u32 value,
				unsigned int count)
{
	void *msg;

	value |= TCU_MBOX_NUM_BYTES(count);
	msg = (void *)(unsigned long)value;
	mbox_send_message(tcu->tx, msg);
	mbox_flush(tcu->tx, 1000);
}

static void tegra_tcu_write(struct tegra_tcu *tcu, const char *s,
			    unsigned int count)
{
	unsigned int written = 0, i = 0;
	bool insert_nl = false;
	u32 value = 0;

	while (i < count) {
		if (insert_nl) {
			value |= TCU_MBOX_BYTE(written++, '\n');
			insert_nl = false;
			i++;
		} else if (s[i] == '\n') {
			value |= TCU_MBOX_BYTE(written++, '\r');
			insert_nl = true;
		} else {
			value |= TCU_MBOX_BYTE(written++, s[i++]);
		}

		if (written == 3) {
			tegra_tcu_write_one(tcu, value, 3);
			value = written = 0;
		}
	}

	if (written)
		tegra_tcu_write_one(tcu, value, written);
}

static void tegra_tcu_uart_start_tx(struct uart_port *port)
{
	struct tegra_tcu *tcu = port->private_data;
	struct tty_port *tport = &port->state->port;
	unsigned char *tail;
	unsigned int count;

	for (;;) {
		count = kfifo_out_linear_ptr(&tport->xmit_fifo, &tail,
				UART_XMIT_SIZE);
		if (!count)
			break;

		tegra_tcu_write(tcu, tail, count);
		uart_xmit_advance(port, count);
	}

	uart_write_wakeup(port);
}

static void tegra_tcu_uart_stop_rx(struct uart_port *port)
{
}

static void tegra_tcu_uart_break_ctl(struct uart_port *port, int ctl)
{
}

static int tegra_tcu_uart_startup(struct uart_port *port)
{
	return 0;
}

static void tegra_tcu_uart_shutdown(struct uart_port *port)
{
}

static void tegra_tcu_uart_set_termios(struct uart_port *port,
				       struct ktermios *new,
				       const struct ktermios *old)
{
}

static const struct uart_ops tegra_tcu_uart_ops = {
	.tx_empty = tegra_tcu_uart_tx_empty,
	.set_mctrl = tegra_tcu_uart_set_mctrl,
	.get_mctrl = tegra_tcu_uart_get_mctrl,
	.stop_tx = tegra_tcu_uart_stop_tx,
	.start_tx = tegra_tcu_uart_start_tx,
	.stop_rx = tegra_tcu_uart_stop_rx,
	.break_ctl = tegra_tcu_uart_break_ctl,
	.startup = tegra_tcu_uart_startup,
	.shutdown = tegra_tcu_uart_shutdown,
	.set_termios = tegra_tcu_uart_set_termios,
};

#if IS_ENABLED(CONFIG_SERIAL_TEGRA_TCU_CONSOLE)
static void tegra_tcu_console_write(struct console *cons, const char *s,
				    unsigned int count)
{
	struct tegra_tcu *tcu = container_of(cons, struct tegra_tcu, console);

	tegra_tcu_write(tcu, s, count);
}

static int tegra_tcu_console_setup(struct console *cons, char *options)
{
	return 0;
}
#endif

static void tegra_tcu_receive(struct mbox_client *cl, void *msg)
{
	struct tegra_tcu *tcu = container_of(cl, struct tegra_tcu, rx_client);
	struct tty_port *port = &tcu->port.state->port;
	u32 value = (u32)(unsigned long)msg;
	unsigned int num_bytes, i;

	num_bytes = TCU_MBOX_NUM_BYTES_V(value);

	for (i = 0; i < num_bytes; i++)
		tty_insert_flip_char(port, TCU_MBOX_BYTE_V(value, i),
				     TTY_NORMAL);

	tty_flip_buffer_push(port);
}

static int tegra_tcu_probe(struct platform_device *pdev)
{
	struct uart_port *port;
	struct tegra_tcu *tcu;
	int err;

	tcu = devm_kzalloc(&pdev->dev, sizeof(*tcu), GFP_KERNEL);
	if (!tcu)
		return -ENOMEM;

	tcu->tx_client.dev = &pdev->dev;
	tcu->rx_client.dev = &pdev->dev;
	tcu->rx_client.rx_callback = tegra_tcu_receive;

	tcu->tx = mbox_request_channel_byname(&tcu->tx_client, "tx");
	if (IS_ERR(tcu->tx)) {
		err = PTR_ERR(tcu->tx);
		dev_err(&pdev->dev, "failed to get tx mailbox: %d\n", err);
		return err;
	}

#if IS_ENABLED(CONFIG_SERIAL_TEGRA_TCU_CONSOLE)
	/* setup the console */
	strcpy(tcu->console.name, "ttyTCU");
	tcu->console.device = uart_console_device;
	tcu->console.flags = CON_PRINTBUFFER | CON_ANYTIME;
	tcu->console.index = -1;
	tcu->console.write = tegra_tcu_console_write;
	tcu->console.setup = tegra_tcu_console_setup;
	tcu->console.data = &tcu->driver;
#endif

	/* setup the driver */
	tcu->driver.owner = THIS_MODULE;
	tcu->driver.driver_name = "tegra-tcu";
	tcu->driver.dev_name = "ttyTCU";
#if IS_ENABLED(CONFIG_SERIAL_TEGRA_TCU_CONSOLE)
	tcu->driver.cons = &tcu->console;
#endif
	tcu->driver.nr = 1;

	err = uart_register_driver(&tcu->driver);
	if (err) {
		dev_err(&pdev->dev, "failed to register UART driver: %d\n",
			err);
		goto free_tx;
	}

	/* setup the port */
	port = &tcu->port;
	spin_lock_init(&port->lock);
	port->dev = &pdev->dev;
	port->type = PORT_TEGRA_TCU;
	port->ops = &tegra_tcu_uart_ops;
	port->fifosize = 1;
	port->iotype = UPIO_MEM;
	port->flags = UPF_BOOT_AUTOCONF;
	port->private_data = tcu;

	err = uart_add_one_port(&tcu->driver, port);
	if (err) {
		dev_err(&pdev->dev, "failed to add UART port: %d\n", err);
		goto unregister_uart;
	}

	/*
	 * Request RX channel after creating port to ensure tcu->port
	 * is ready for any immediate incoming bytes.
	 */
	tcu->rx = mbox_request_channel_byname(&tcu->rx_client, "rx");
	if (IS_ERR(tcu->rx)) {
		err = PTR_ERR(tcu->rx);
		dev_err(&pdev->dev, "failed to get rx mailbox: %d\n", err);
		goto remove_uart_port;
	}

	platform_set_drvdata(pdev, tcu);
#if IS_ENABLED(CONFIG_SERIAL_TEGRA_TCU_CONSOLE)
	register_console(&tcu->console);
#endif

	return 0;

remove_uart_port:
	uart_remove_one_port(&tcu->driver, &tcu->port);
unregister_uart:
	uart_unregister_driver(&tcu->driver);
free_tx:
	mbox_free_channel(tcu->tx);

	return err;
}

static void tegra_tcu_remove(struct platform_device *pdev)
{
	struct tegra_tcu *tcu = platform_get_drvdata(pdev);

#if IS_ENABLED(CONFIG_SERIAL_TEGRA_TCU_CONSOLE)
	unregister_console(&tcu->console);
#endif
	mbox_free_channel(tcu->rx);
	uart_remove_one_port(&tcu->driver, &tcu->port);
	uart_unregister_driver(&tcu->driver);
	mbox_free_channel(tcu->tx);
}

static const struct of_device_id tegra_tcu_match[] = {
	{ .compatible = "nvidia,tegra194-tcu" },
	{ }
};
MODULE_DEVICE_TABLE(of, tegra_tcu_match);

static struct platform_driver tegra_tcu_driver = {
	.driver = {
		.name = "tegra-tcu",
		.of_match_table = tegra_tcu_match,
	},
	.probe = tegra_tcu_probe,
	.remove_new = tegra_tcu_remove,
};
module_platform_driver(tegra_tcu_driver);

MODULE_AUTHOR("Mikko Perttunen <mperttunen@nvidia.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("NVIDIA Tegra Combined UART driver");
