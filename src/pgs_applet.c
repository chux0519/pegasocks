#include "pgs_applet.h"

#ifdef WITH_APPLET

static pgs_tray_t tray;

static void toggle_cb(pgs_tray_menu_t *item)
{
	printf("toggle cb\n");
	item->checked = !item->checked;
	tray_update(&tray);
}

static void hello_cb(pgs_tray_menu_t *item)
{
	(void)item;
	printf("hello cb\n");
	item->checked = !item->checked;
	if (item->checked) {
		item->text = "on";
	} else {
		item->text = "off";
	}
	if (strcmp(tray.icon, TRAY_ICON1) == 0) {
		tray.icon = TRAY_ICON2;
	} else {
		tray.icon = TRAY_ICON1;
	}
	tray_update(&tray);
}

static void quit_cb(pgs_tray_menu_t *item)
{
	(void)item;
	printf("quit cb\n");
	// TODO: clean
	tray_exit();
}

static void submenu_cb(pgs_tray_menu_t *item)
{
	(void)item;
	printf("submenu: clicked on %s, index: %d\n", item->text,
	       item->context);
	tray_update(&tray);
}

static pgs_tray_t tray = {
	.icon = TRAY_ICON1,
	.menu =
		(pgs_tray_menu_t[]){
			{ .text = "on", .cb = hello_cb, .checked = 1 },
			{ .text = "-" },
			{
				.text = "servers",
				// .submenu =
				//   (struct tray_menu[]){
				// 	  { .text = "* ramnow.online(trojan)",
				// 	    .checked = 1,
				// 	    .cb = submenu_cb,
				// 	    .context = 0 },
				// 	  { .text = "g_204: 100ms\tping: 200ms",
				// 	    .disabled = 1 },
				// 	  { .text = "-" },
				// 	  { .text = "hexyoungs.club(trojan)",
				// 	    .checked = 0,
				// 	    .cb = submenu_cb,
				// 	    .context = 1 },
				// 	  { .text = "g_204: 100ms\tping: 200ms",
				// 	    .disabled = 1 },
				// 	  { .text = "-" },
				// 	  { .text = "pegas.ramnow.online(v2ray)",
				// 	    .checked = 0,
				// 	    .cb = submenu_cb,
				// 	    .context = 2 },
				// 	  { .text = "g_204: 100ms\tping: 200ms",
				// 	    .disabled = 1 },
				// 	  { .text = "-" },
				// 	  { .text = NULL } }
			},
			{ .text = "-" },
			{ .text = "quit", .cb = quit_cb },
			{ .text = NULL } },
};

// init submenu
void pgs_tray_init(pgs_tray_context_t *ctx)
{
	// TODO: init servers
}
// clean submenu
void pgs_tray_clean()
{
}

// TODO: recv args(thread handles, metrics server, configs)
void pgs_tray_start(pgs_tray_context_t *ctx)
{
	pgs_tray_init(ctx);
	if (tray_init(&tray) < 0) {
		printf("failed to create tray\n");
		return 1;
	}
	int iter = 0;
	while (tray_loop(1) == 0) {
		if (++iter % 5 == 0) {
			// TODO: update metrics, every 5 iteration
			printf("should update state\n");
			iter = 0;
		}
		printf("iteration\n");
	}
	pgs_tray_clean();
}

#else
void pgs_tran_start(pgs_tray_context_t *ctx)
{
}

#endif

