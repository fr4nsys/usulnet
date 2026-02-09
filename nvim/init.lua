-- ==========================================================================
-- usulnet nvim config — /opt/usulnet/nvim-config/init.lua
-- Lazy.nvim + Treesitter + Telescope + usulnet theme
-- ==========================================================================

-- Leader key (before plugins)
vim.g.mapleader = " "
vim.g.maplocalleader = " "

-- ==========================================================================
-- Options
-- ==========================================================================
local opt = vim.opt

opt.number         = true
opt.relativenumber = true
opt.signcolumn     = "yes"
opt.cursorline     = true
opt.termguicolors  = true
opt.mouse          = "a"
opt.clipboard      = "unnamedplus"
opt.undofile       = true
opt.swapfile       = false
opt.backup         = false
opt.writebackup    = false

-- Indentation
opt.tabstop     = 4
opt.shiftwidth  = 4
opt.softtabstop = 4
opt.expandtab   = false
opt.smartindent = true
opt.autoindent  = true

-- Search
opt.ignorecase = true
opt.smartcase  = true
opt.hlsearch   = true
opt.incsearch  = true

-- UI
opt.scrolloff     = 8
opt.sidescrolloff = 8
opt.wrap          = false
opt.showmode      = false
opt.splitbelow    = true
opt.splitright    = true
opt.pumheight     = 10
opt.completeopt   = "menuone,noselect"
opt.laststatus    = 3 -- global statusline
opt.cmdheight     = 1
opt.updatetime    = 250
opt.timeoutlen    = 300

-- Shorter messages
opt.shortmess:append("cI")

-- Fill chars
opt.fillchars = { eob = " ", fold = " ", diff = "╱" }

-- ==========================================================================
-- Bootstrap lazy.nvim
-- ==========================================================================
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not vim.loop.fs_stat(lazypath) then
  vim.fn.system({
    "git", "clone", "--filter=blob:none",
    "https://github.com/folke/lazy.nvim.git",
    "--branch=stable",
    lazypath,
  })
end
vim.opt.rtp:prepend(lazypath)

-- ==========================================================================
-- Plugins
-- ==========================================================================
require("lazy").setup({
  -- Treesitter
  {
    "nvim-treesitter/nvim-treesitter",
    build = ":TSUpdate",
    event = { "BufReadPre", "BufNewFile" },
    config = function()
      -- Use the new opts-based API (nvim-treesitter.configs was removed in newer versions)
      local ok, ts_configs = pcall(require, "nvim-treesitter.configs")
      if ok then
        -- Legacy API (older nvim-treesitter versions)
        ts_configs.setup({
          ensure_installed = {
            "go", "gomod", "gosum", "gowork",
            "lua", "luadoc",
            "python", "rust", "c", "cpp",
            "javascript", "typescript", "tsx", "html", "css",
            "json", "yaml", "toml",
            "bash", "fish",
            "sql",
            "dockerfile",
            "markdown", "markdown_inline",
            "diff", "gitcommit", "git_rebase",
            "regex", "vim", "vimdoc",
            "templ",
          },
          auto_install = true,
          highlight = {
            enable = true,
            additional_vim_regex_highlighting = false,
          },
          indent = { enable = true },
          incremental_selection = {
            enable = true,
            keymaps = {
              init_selection    = "<C-space>",
              node_incremental  = "<C-space>",
              scope_incremental = false,
              node_decremental  = "<BS>",
            },
          },
        })
      else
        -- New API (nvim-treesitter >= 1.0): use vim.treesitter directly
        -- ensure_installed is handled by the build = ":TSUpdate" command
        vim.treesitter.language.register("bash", "sh")
      end
    end,
  },

  -- Telescope
  {
    "nvim-telescope/telescope.nvim",
    branch = "0.1.x",
    dependencies = {
      "nvim-lua/plenary.nvim",
      {
        "nvim-telescope/telescope-fzf-native.nvim",
        build = "which make >/dev/null 2>&1 && make || true",
      },
    },
    cmd = "Telescope",
    keys = {
      { "<leader>ff", "<cmd>Telescope find_files<cr>",  desc = "Find Files" },
      { "<leader>fg", "<cmd>Telescope live_grep<cr>",   desc = "Live Grep" },
      { "<leader>fb", "<cmd>Telescope buffers<cr>",     desc = "Buffers" },
      { "<leader>fh", "<cmd>Telescope help_tags<cr>",   desc = "Help Tags" },
      { "<leader>fr", "<cmd>Telescope oldfiles<cr>",    desc = "Recent Files" },
      { "<leader>/",  "<cmd>Telescope current_buffer_fuzzy_find<cr>", desc = "Fuzzy Search Buffer" },
    },
    config = function()
      local telescope = require("telescope")
      telescope.setup({
        defaults = {
          prompt_prefix   = "  ",
          selection_caret = " ",
          path_display    = { "truncate" },
          sorting_strategy = "ascending",
          layout_config = {
            horizontal = { prompt_position = "top", preview_width = 0.55 },
          },
        },
      })
      pcall(telescope.load_extension, "fzf")
    end,
  },

  -- Mini.pairs (auto-close brackets)
  {
    "echasnovski/mini.pairs",
    event = "InsertEnter",
    opts = {},
  },

  -- Mini.comment
  {
    "echasnovski/mini.comment",
    event = "VeryLazy",
    opts = {},
  },

  -- Mini.surround
  {
    "echasnovski/mini.surround",
    event = "VeryLazy",
    opts = {},
  },

  -- Indent guides
  {
    "lukas-reineke/indent-blankline.nvim",
    main = "ibl",
    event = { "BufReadPre", "BufNewFile" },
    opts = {
      indent = { char = "│", tab_char = "│" },
      scope  = { enabled = true, show_start = false, show_end = false },
    },
  },

  -- Git signs
  {
    "lewis6991/gitsigns.nvim",
    event = { "BufReadPre", "BufNewFile" },
    opts = {
      signs = {
        add          = { text = "▎" },
        change       = { text = "▎" },
        delete       = { text = "" },
        topdelete    = { text = "" },
        changedelete = { text = "▎" },
      },
    },
  },

  -- Which-key
  {
    "folke/which-key.nvim",
    event = "VeryLazy",
    opts = {
      plugins = { spelling = true },
    },
  },

  -- Status line (lualine)
  {
    "nvim-lualine/lualine.nvim",
    event = "VeryLazy",
    opts = {
      options = {
        theme = "auto",
        globalstatus = true,
        component_separators = { left = "", right = "" },
        section_separators   = { left = "", right = "" },
      },
      sections = {
        lualine_a = { "mode" },
        lualine_b = { "branch", "diff", "diagnostics" },
        lualine_c = { { "filename", path = 1 } },
        lualine_x = { "encoding", "filetype" },
        lualine_y = { "progress" },
        lualine_z = { "location" },
      },
    },
  },

}, {
  -- lazy.nvim config
  install = { colorscheme = { "usulnet" } },
  checker = { enabled = false }, -- no auto-update in editor sessions
  performance = {
    rtp = {
      disabled_plugins = {
        "gzip", "matchit", "matchparen", "netrwPlugin",
        "tarPlugin", "tohtml", "tutor", "zipPlugin",
      },
    },
  },
})

-- ==========================================================================
-- usulnet Colorscheme
-- Matches the platform's dark theme: bg #0d1117, accent #ff6b35
-- ==========================================================================
local function setup_usulnet_theme()
  vim.cmd("hi clear")
  vim.g.colors_name = "usulnet"

  local hl = function(group, opts) vim.api.nvim_set_hl(0, group, opts) end

  -- Palette
  local bg       = "#0d1117"
  local bg_float = "#161b22"
  local bg_line  = "#161b22"
  local bg_sel   = "#1c2633"
  local fg       = "#e6edf3"
  local fg_dim   = "#8b949e"
  local fg_dark  = "#484f58"
  local border   = "#30363d"

  local accent   = "#ff6b35"   -- usulnet primary
  local red      = "#f85149"
  local green    = "#3fb950"
  local yellow   = "#d29922"
  local blue     = "#58a6ff"
  local magenta  = "#bc8cff"
  local cyan     = "#76e3ea"
  local orange   = "#ffa657"

  -- Base UI
  hl("Normal",       { fg = fg,     bg = bg })
  hl("NormalFloat",  { fg = fg,     bg = bg_float })
  hl("FloatBorder",  { fg = border, bg = bg_float })
  hl("CursorLine",   { bg = bg_line })
  hl("CursorLineNr", { fg = accent, bold = true })
  hl("LineNr",       { fg = fg_dark })
  hl("SignColumn",   { bg = bg })
  hl("FoldColumn",   { fg = fg_dark, bg = bg })
  hl("Folded",       { fg = fg_dim, bg = bg_float })
  hl("Visual",       { bg = bg_sel })
  hl("VisualNOS",    { bg = bg_sel })
  hl("Search",       { fg = bg, bg = yellow })
  hl("IncSearch",    { fg = bg, bg = accent })
  hl("CurSearch",    { fg = bg, bg = accent })
  hl("Substitute",   { fg = bg, bg = red })
  hl("MatchParen",   { fg = accent, bold = true, underline = true })
  hl("Pmenu",        { fg = fg, bg = bg_float })
  hl("PmenuSel",     { fg = fg, bg = bg_sel })
  hl("PmenuSbar",    { bg = border })
  hl("PmenuThumb",   { bg = fg_dim })
  hl("WinSeparator", { fg = border })
  hl("StatusLine",   { fg = fg_dim, bg = bg_float })
  hl("StatusLineNC", { fg = fg_dark, bg = bg_float })
  hl("TabLine",      { fg = fg_dim, bg = bg_float })
  hl("TabLineFill",  { bg = bg })
  hl("TabLineSel",   { fg = accent, bg = bg, bold = true })
  hl("WildMenu",     { fg = bg, bg = accent })
  hl("Directory",    { fg = blue })
  hl("Title",        { fg = accent, bold = true })
  hl("MoreMsg",      { fg = green })
  hl("Question",     { fg = green })
  hl("WarningMsg",   { fg = yellow })
  hl("ErrorMsg",     { fg = red })
  hl("NonText",      { fg = fg_dark })
  hl("SpecialKey",   { fg = fg_dark })
  hl("Whitespace",   { fg = fg_dark })
  hl("EndOfBuffer",  { fg = bg })

  -- Diff
  hl("DiffAdd",    { bg = "#0d2818" })
  hl("DiffChange", { bg = "#1c1d00" })
  hl("DiffDelete", { bg = "#2d0000" })
  hl("DiffText",   { bg = "#3a3000" })

  -- Diagnostics
  hl("DiagnosticError", { fg = red })
  hl("DiagnosticWarn",  { fg = yellow })
  hl("DiagnosticInfo",  { fg = blue })
  hl("DiagnosticHint",  { fg = cyan })
  hl("DiagnosticUnderlineError", { undercurl = true, sp = red })
  hl("DiagnosticUnderlineWarn",  { undercurl = true, sp = yellow })
  hl("DiagnosticUnderlineInfo",  { undercurl = true, sp = blue })
  hl("DiagnosticUnderlineHint",  { undercurl = true, sp = cyan })

  -- Syntax (Treesitter + legacy)
  hl("Comment",    { fg = fg_dim, italic = true })
  hl("Constant",   { fg = blue })
  hl("String",     { fg = "#a5d6ff" })
  hl("Character",  { fg = "#a5d6ff" })
  hl("Number",     { fg = "#79c0ff" })
  hl("Boolean",    { fg = "#79c0ff" })
  hl("Float",      { fg = "#79c0ff" })
  hl("Identifier", { fg = fg })
  hl("Function",   { fg = magenta })
  hl("Statement",  { fg = red })
  hl("Keyword",    { fg = red })
  hl("Conditional",{ fg = red })
  hl("Repeat",     { fg = red })
  hl("Label",      { fg = blue })
  hl("Operator",   { fg = red })
  hl("Exception",  { fg = red })
  hl("PreProc",    { fg = red })
  hl("Include",    { fg = red })
  hl("Define",     { fg = red })
  hl("Macro",      { fg = blue })
  hl("Type",       { fg = orange })
  hl("StorageClass", { fg = red })
  hl("Structure",  { fg = orange })
  hl("Typedef",    { fg = orange })
  hl("Special",    { fg = cyan })
  hl("SpecialChar",{ fg = cyan })
  hl("Tag",        { fg = green })
  hl("Delimiter",  { fg = fg })
  hl("Debug",      { fg = orange })
  hl("Underlined", { underline = true })
  hl("Error",      { fg = red })
  hl("Todo",       { fg = bg, bg = accent, bold = true })

  -- Treesitter semantic tokens
  hl("@variable",          { fg = fg })
  hl("@variable.builtin",  { fg = red })
  hl("@variable.parameter",{ fg = fg })
  hl("@variable.member",   { fg = fg })
  hl("@constant",          { fg = blue })
  hl("@constant.builtin",  { fg = blue })
  hl("@module",            { fg = orange })
  hl("@string",            { fg = "#a5d6ff" })
  hl("@string.escape",     { fg = cyan })
  hl("@string.regex",      { fg = green })
  hl("@character",         { fg = "#a5d6ff" })
  hl("@number",            { fg = "#79c0ff" })
  hl("@boolean",           { fg = "#79c0ff" })
  hl("@type",              { fg = orange })
  hl("@type.builtin",      { fg = orange })
  hl("@type.definition",   { fg = orange })
  hl("@attribute",         { fg = orange })
  hl("@property",          { fg = fg })
  hl("@function",          { fg = magenta })
  hl("@function.builtin",  { fg = magenta })
  hl("@function.call",     { fg = magenta })
  hl("@function.method",   { fg = magenta })
  hl("@constructor",       { fg = orange })
  hl("@keyword",           { fg = red })
  hl("@keyword.function",  { fg = red })
  hl("@keyword.return",    { fg = red })
  hl("@keyword.operator",  { fg = red })
  hl("@keyword.import",    { fg = red })
  hl("@keyword.conditional", { fg = red })
  hl("@keyword.repeat",    { fg = red })
  hl("@keyword.exception", { fg = red })
  hl("@operator",          { fg = red })
  hl("@punctuation.bracket",   { fg = fg })
  hl("@punctuation.delimiter", { fg = fg_dim })
  hl("@punctuation.special",   { fg = cyan })
  hl("@comment",           { fg = fg_dim, italic = true })
  hl("@tag",               { fg = green })
  hl("@tag.attribute",     { fg = blue })
  hl("@tag.delimiter",     { fg = fg_dim })

  -- LSP
  hl("LspReferenceText",  { bg = bg_sel })
  hl("LspReferenceRead",  { bg = bg_sel })
  hl("LspReferenceWrite", { bg = bg_sel })

  -- Telescope
  hl("TelescopeNormal",        { fg = fg, bg = bg_float })
  hl("TelescopeBorder",        { fg = border, bg = bg_float })
  hl("TelescopePromptNormal",  { fg = fg, bg = bg_float })
  hl("TelescopePromptBorder",  { fg = accent, bg = bg_float })
  hl("TelescopePromptTitle",   { fg = bg, bg = accent, bold = true })
  hl("TelescopePreviewTitle",  { fg = bg, bg = green, bold = true })
  hl("TelescopeResultsTitle",  { fg = bg, bg = blue, bold = true })
  hl("TelescopeSelection",     { bg = bg_sel })
  hl("TelescopeMatching",      { fg = accent, bold = true })

  -- Gitsigns
  hl("GitSignsAdd",    { fg = green })
  hl("GitSignsChange", { fg = yellow })
  hl("GitSignsDelete", { fg = red })

  -- Indent-blankline
  hl("IblIndent", { fg = "#21262d" })
  hl("IblScope",  { fg = "#30363d" })

  -- Which-key
  hl("WhichKey",          { fg = accent })
  hl("WhichKeyGroup",     { fg = blue })
  hl("WhichKeySeparator", { fg = fg_dark })
  hl("WhichKeyDesc",      { fg = fg })
  hl("WhichKeyFloat",     { bg = bg_float })

  -- Lazy.nvim
  hl("LazyButton",       { fg = fg, bg = bg_sel })
  hl("LazyButtonActive", { fg = bg, bg = accent, bold = true })
  hl("LazyH1",           { fg = bg, bg = accent, bold = true })
end

setup_usulnet_theme()

-- ==========================================================================
-- Keymaps
-- ==========================================================================
local map = vim.keymap.set

-- Better navigation
map("n", "<C-d>", "<C-d>zz", { desc = "Scroll down centered" })
map("n", "<C-u>", "<C-u>zz", { desc = "Scroll up centered" })
map("n", "n",     "nzzzv",   { desc = "Next search centered" })
map("n", "N",     "Nzzzv",   { desc = "Prev search centered" })

-- Better indenting
map("v", "<", "<gv")
map("v", ">", ">gv")

-- Move lines
map("v", "J", ":m '>+1<CR>gv=gv", { silent = true, desc = "Move selection down" })
map("v", "K", ":m '<-2<CR>gv=gv", { silent = true, desc = "Move selection up" })

-- Buffer navigation
map("n", "<S-h>", "<cmd>bprevious<cr>", { desc = "Prev buffer" })
map("n", "<S-l>", "<cmd>bnext<cr>",     { desc = "Next buffer" })

-- Window navigation
map("n", "<C-h>", "<C-w>h", { desc = "Go to left window" })
map("n", "<C-j>", "<C-w>j", { desc = "Go to lower window" })
map("n", "<C-k>", "<C-w>k", { desc = "Go to upper window" })
map("n", "<C-l>", "<C-w>l", { desc = "Go to right window" })

-- Clear search highlight
map("n", "<Esc>", "<cmd>nohlsearch<cr>", { desc = "Clear search highlight" })

-- Quick save (:w triggers the BufWritePost autocmd → commits to Gitea)
map("n", "<leader>w", "<cmd>w<cr>", { desc = "Save (commit to Gitea)" })

-- Quick quit
map("n", "<leader>q", "<cmd>q<cr>",  { desc = "Quit" })
map("n", "<leader>Q", "<cmd>qa!<cr>", { desc = "Force quit all" })

-- Diagnostic navigation
map("n", "[d", vim.diagnostic.goto_prev, { desc = "Prev diagnostic" })
map("n", "]d", vim.diagnostic.goto_next, { desc = "Next diagnostic" })

-- ==========================================================================
-- Autocmds
-- ==========================================================================

local augroup = vim.api.nvim_create_augroup("usulnet", { clear = true })

-- Highlight on yank
vim.api.nvim_create_autocmd("TextYankPost", {
  group = augroup,
  callback = function()
    vim.highlight.on_yank({ higroup = "IncSearch", timeout = 200 })
  end,
})

-- Restore cursor position
vim.api.nvim_create_autocmd("BufReadPost", {
  group = augroup,
  callback = function(args)
    local mark = vim.api.nvim_buf_get_mark(args.buf, '"')
    local count = vim.api.nvim_buf_line_count(args.buf)
    if mark[1] > 0 and mark[1] <= count then
      pcall(vim.api.nvim_win_set_cursor, 0, mark)
    end
  end,
})

-- Auto-resize splits on terminal resize
vim.api.nvim_create_autocmd("VimResized", {
  group = augroup,
  callback = function() vim.cmd("tabdo wincmd =") end,
})

-- Filetype overrides
vim.api.nvim_create_autocmd("FileType", {
  group = augroup,
  pattern = { "go", "make", "gitconfig" },
  callback = function()
    vim.opt_local.expandtab = false
    vim.opt_local.tabstop = 4
    vim.opt_local.shiftwidth = 4
  end,
})

vim.api.nvim_create_autocmd("FileType", {
  group = augroup,
  pattern = { "lua", "yaml", "json", "html", "css", "javascript", "typescript" },
  callback = function()
    vim.opt_local.expandtab = true
    vim.opt_local.tabstop = 2
    vim.opt_local.shiftwidth = 2
  end,
})

-- ==========================================================================
-- Diagnostic config
-- ==========================================================================
vim.diagnostic.config({
  underline      = true,
  virtual_text   = { spacing = 4, prefix = "●" },
  signs          = true,
  update_in_insert = false,
  severity_sort  = true,
  float = {
    border = "rounded",
    source = "always",
  },
})

-- Diagnostic signs
local signs = { Error = " ", Warn = " ", Hint = " ", Info = " " }
for type, icon in pairs(signs) do
  local hl = "DiagnosticSign" .. type
  vim.fn.sign_define(hl, { text = icon, texthl = hl, numhl = "" })
end
