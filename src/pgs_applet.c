#include "pgs_applet.h"

#ifdef WITH_APPLET

static pgs_tray_t tray;

static void toggle_cb(pgs_tray_menu_t *item)
{
	printf("toggle cb\n");
	item->checked = !item->checked;
	tray_update(&tray);
}

static void on_off_cb(pgs_tray_menu_t *item)
{
	(void)item;
	pgs_tray_context_t *ctx = item->context;
	item->checked = !item->checked;
	pgs_logger_info(ctx->logger, "turn pegas %s", item->text);
	// TODO: shutdown all worker threads
	// TODO: or spawn all worker threads
	item->text = item->checked ? "on" : "off";
	tray.icon = item->checked ? TRAY_ICON1 : TRAY_ICON2;
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
			{ .text = "on", .cb = on_off_cb, .checked = 1 },
			{ .text = "-" },
			{
				.text = "servers",
			},
			{ .text = "-" },
			{ .text = "quit", .cb = quit_cb },
			{ .text = NULL } },
};

void pgs_tray_submenu_update(pgs_tray_context_t *ctx,
			     pgs_tray_menu_t *servers_submenu)
{
	for (int i = 0; i < ctx->sm->server_len * 3; i += 3) {
		int server_idx = i / 3;
		servers_submenu[i].text =
			ctx->sm->server_configs[server_idx].server_address;
		servers_submenu[i].checked =
			server_idx == ctx->sm->cur_server_index;
		// TODO: metrics
		servers_submenu[i + 1].text = "metrics: TODO";
		servers_submenu[i + 1].disabled = 1;
		servers_submenu[i + 2].text = "-";
	}
	servers_submenu[ctx->sm->server_len * 3 - 1].text = NULL;
}

// init submenu
void pgs_tray_init(pgs_tray_context_t *ctx)
{
	pgs_logger_info(ctx->logger, "current server: %d, server length: %d",
			ctx->sm->cur_server_index, ctx->sm->server_len);
	pgs_tray_menu_t *servers_submenu =
		pgs_malloc(sizeof(pgs_tray_menu_t) * ctx->sm->server_len * 3);
	pgs_tray_submenu_update(ctx, servers_submenu);
	tray.menu[2].submenu = servers_submenu;
	tray.menu[0].context = ctx;
}
// clean submenu
void pgs_tray_clean()
{
	if (tray.menu[2].submenu)
		pgs_free(tray.menu[2].submenu);
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
			// printf("should update state\n");
			iter = 0;
		}
		// printf("iteration\n");
	}
	pgs_tray_clean();
}

#else
void pgs_tran_start(pgs_tray_context_t *ctx)
{
}

#endif

