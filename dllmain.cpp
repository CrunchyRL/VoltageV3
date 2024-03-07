#include "Components/Includes.hpp"
#include <functional>
#include <DirectXMath.h>
#include <io.h>

using namespace DirectX;

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved);

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

using namespace nlohmann;

HMODULE hModule;
Present oPresent;
HWND window = NULL;
WNDPROC oWndProc;
ID3D11Device* pDevice = NULL;
ID3D11DeviceContext* pContext = NULL;
ID3D11RenderTargetView* mainRenderTargetView;
ID3D11ShaderResourceView* my_texture = NULL;
LPVOID pThreadParameter = NULL;
bool dothingieonetime = true;
json SetCategories;
SInventoryItem CurrentInventoryItem = { 69420 };

void InitImGui()
{
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.ConfigFlags = ImGuiConfigFlags_NoMouseCursorChange;
	ImGui_ImplWin32_Init(window);
	ImGui_ImplDX11_Init(pDevice, pContext);
	ImGui::SetNextWindowSizeConstraints(ImVec2{ 970, 520 }, ImVec2{ 970, 520 });
	if (dothingieonetime) {
		auto io = ImGui::GetIO();
		if (io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\Calibri.ttf", 15))
			io.FontDefault = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\Calibri.ttf", 15);
		dothingieonetime = false;
	}
}

bool needtoinitcore = true;
char itemToFind[64];
int psyPongCount;
std::string lastPsyNetLog;

const int BUFSIZE = 4096;
unsigned char key[32];
unsigned char iv[16];

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	ImGuiIO& io = ImGui::GetIO();

	POINT mPos;
	GetCursorPos(&mPos);
	ScreenToClient(window, &mPos);
	ImGui::GetIO().MousePos.x = mPos.x;
	ImGui::GetIO().MousePos.y = mPos.y;

	if (uMsg == WM_KEYUP)
	{
		bool HITKEY(wParam == VK_F9);

		if (HITKEY)
		{
			//Console.Write("MEow");
			Events.iswindowactive = !Events.iswindowactive;
			try {
				std::ifstream stream("Voltage\\itemsets.json");
				if (stream.good())
				{
					json TheJson = json::parse(stream);
					SetCategories = TheJson["SetCategories"];
				}
			}

			catch (json::parse_error& e) {
				Console.Error(e.what());
			}
			catch (json::exception& e) {
				Console.Error(e.what());	
			}
		}
	}

	if (Events.iswindowactive && io.WantCaptureMouse)
	{
		ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam);
		return true;
	}

	return CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam);
}

namespace fs = std::filesystem;

std::vector<std::string> ListJSONFiles(const std::string& folderPath) {
	std::vector<std::string> jsonFiles;
	for (const auto& entry : fs::directory_iterator(folderPath)) {
		if (entry.path().extension() == ".json") {
			jsonFiles.push_back(entry.path().filename().string());
		}
	}
	return jsonFiles;
}

void SaveKeybindsToFile(const std::vector<JsonKeybindAssociation>& associations) {
	json keybindsData;
	for (const JsonKeybindAssociation& association : associations) {
		keybindsData[association.jsonFilePath] = association.keybind;
	}

	std::ofstream keybindsFile("keybinds.json");
	keybindsFile << std::setw(4) << keybindsData << std::endl;
	keybindsFile.close();
}

ImVec4 HEXAtoIV4(const char* hex, float a) {
	int r, g, b;
	std::sscanf(hex, "%02x%02x%02x", &r, &g, &b);
	return ImVec4(r, g, b, a);
}

void SelectableColor(ImU32 color)
{
	ImVec2 p_min = ImGui::GetItemRectMin();
	ImVec2 p_max = ImGui::GetItemRectMax();
	ImGui::GetWindowDrawList()->AddRectFilled(p_min, p_max, color);
}

std::string clean_json(const std::string str) {
	std::string sanitizedString = "";
	for (int i = 0; i < str.length(); i++) {
		if (isalnum(str[i])) {
			sanitizedString += str[i];
		}
	}
	return sanitizedString;
}

static int totalpsynet = 0;
static int switchTabs = 9;
bool closingthecum = false;
bool* istrafficmenuopen;
bool init = false;
int numberoftimesthecum = 0;
static int currentmenubg = 0;
int CurrentItem;
int ItemsCurrentItem;
bool isrankselected;
static const char* menubglistbox_items[16] = { "Stadium", "Utopia Snow", "Haunted Station", "Beach", "Beach Night", "Halloween", "China", "Park Day", "Music", "Throwback Hockey", "Circuit", "Outlaw", "Arc", "Park Snowy", "Tokyo Toon", "Utopia Lux" };
static const char* ranklistbox_items[8] = { "Bronze", "Silver", "Gold", "Platinum", "Diamond", "Champion", "Grand Champion", "Supersonic Legend" };
static int selected_rankitem = 0;
int unauthedtick;
bool istitleselected = false;
int width = 85;
int rankDivision = 0;
bool itemlistopen = false;
bool isitemlistopen = false;
std::string searchText = "";
ImGuiTextFilter productFilter;
// Define a bool to keep track of keybind selection mode
bool keybindSelectionMode = false;

// Define a map to store keybinds for each JSON file
std::map<std::string, int> fileKeybinds;


bool is_base64(const std::string& s) {
	static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if (s.length() % 4 != 0) {
		return false;
	}

	size_t padding = 0;
	if (s.length() > 1 && s[s.length() - 1] == '=') {
		padding++;
	}
	if (s.length() > 2 && s[s.length() - 2] == '=') {
		padding++;
	}

	for (size_t i = 0; i < s.length(); i++) {
		if (base64_chars.find(s[i]) == std::string::npos && s[i] != '=') {
			return false;
		}
	}

	return true;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
	std::vector<std::string> tokens;
	std::string token;
	for (char c : s) {
		if (c == delimiter) {
			tokens.push_back(token);
			token.clear();
		}
		else {
			token += c;
		}
	}
	if (!token.empty()) {
		tokens.push_back(token);
	}
	return tokens;
}

std::string DecodePartyMessage(std::string input_string) {
	std::size_t left_bracket_pos = input_string.find("{");
	std::size_t right_bracket_pos = input_string.rfind("}");
	if (left_bracket_pos != std::string::npos && right_bracket_pos != std::string::npos) {
		std::string json_str = input_string.substr(left_bracket_pos, right_bracket_pos - left_bracket_pos + 1);
		json j = json::parse(json_str);
		std::string class_name = input_string.substr(0, left_bracket_pos);
		std::string valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789|_.";

		class_name.erase(std::remove_if(class_name.begin(), class_name.end(),
			[valid_chars](char c) { return valid_chars.find(c) == std::string::npos; }), class_name.end());

		j["Class"] = class_name;
		return j.dump();
	}
	else {
		// JSON object not found in the input string
		return "";
	}
}

json jwt_to_json(const std::string& jwt) {
	// Extract the header, payload, and signature from the JWT
	std::string header_encoded = jwt.substr(0, jwt.find_first_of('.'));
	std::string payload_encoded = jwt.substr(jwt.find_first_of('.') + 1, jwt.find_last_of('.') - jwt.find_first_of('.') - 1);
	std::string signature_encoded = jwt.substr(jwt.find_last_of('.') + 1);

	// Decode the header and payload
	std::string header = Instances.base64_decode(header_encoded);
	std::string payload = Instances.base64_decode(payload_encoded);

	// Convert the decoded header and payload to a JSON string using nlohmann library
	json j;
	j["header"] = json::parse(header);
	j["payload"] = json::parse(payload);

	return j;
}

bool is_jwt(const std::string& str) {
	std::regex jwt_regex(R"(([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+))");
	std::smatch match;
	if (std::regex_match(str, match, jwt_regex)) {
		// Check if the first and second parts are base64-encoded JSON strings
		try {
			std::string header = Instances.base64_decode(match[1].str());
			std::string payload = Instances.base64_decode(match[2].str());
			json::parse(header);
			json::parse(payload);
			return true;
		}
		catch (const std::exception& e) {
			return false;
		}
	}
	return false;
}

bool datastorelogger = false;
bool opendatastorebutton = false;

void LogDatastoreValues()
{
	UGFxDataStore_X* store = Events.dataStore;

	if (store) {
		// Create an ImGui window
		ImGui::Begin("Datastore Values", &datastorelogger);

		TArray<struct FGFxDataStoreTable> t = store->Tables;
		for (int i = 0; i < t.Num(); i++) {
			// Create a collapsible section for each table
			if (ImGui::CollapsingHeader(("Table: " + t.At(i).Name.ToString()).c_str())) {
				ImGui::Text("Rows:");
				ImGui::Indent();

				TArray<struct FGFxDataStoreRow> rows = t.At(i).Rows;
				for (int k = 0; k < rows.Num(); k++) {
					if (!rows.At(k).BoundObject)
						continue;

					ImGui::Text(("RowIndex " + std::to_string(k)).c_str());
					ImGui::Text("%d", rows.At(k).BoundObject->RowIndex);
				}

				ImGui::Unindent();

				ImGui::Text("Columns:");
				ImGui::Indent();

				TArray<struct FGFxDataStoreColumn> columns = t.At(i).Columns;
				for (int j = 0; j < columns.Num(); j++) {
					ImGui::Text(columns.At(j).Name.ToString().c_str());
				}

				ImGui::Unindent();
			}
		}

		ImGui::End();
	}
}

void display_json(nlohmann::json json_obj) {
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.70196, 0.70196, 0.70196, 1.f });

	if (json_obj.is_null()) {
		ImGui::Text("{}");
		return;
	}

	if (json_obj.empty()) {
		ImGui::Text("{}");
		return;
	}

	for (const auto& it : json_obj.items()) {
		ImGui::Indent(20);
		ImGui::Bullet();
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.70196, 0.70196, 0.70196, 1.f });
		ImGui::Text("%s: ", it.key().c_str());
		ImGui::PopStyleColor();
		ImGui::Unindent(20);
		ImGui::SameLine();

		if (it.value().is_object()) {
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.26f, 0.59f, 0.98f, 0.3f });
			ImGui::Text("Object");
			ImGui::PopStyleColor();
			ImGui::Indent();
			display_json(it.value());
			ImGui::Unindent();
		}
		else if (it.value().is_array()) {
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.98f, 0.39f, 0.39f, 0.3f });
			ImGui::Text("Array[%d]", it.value().size());
			ImGui::PopStyleColor();
			for (int i = 0; i < it.value().size(); i++) {
				ImGui::Indent();
				ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.98f, 0.39f, 0.39f, 0.3f });
				ImGui::Text("[%d] - ", i);
				ImGui::PopStyleColor();
				if (it.value()[i].is_null()) {
					ImGui::SameLine();
					ImGui::Text("\"%s\"", "{}");
					ImGui::PopStyleColor();
				}
				if (it.value()[i].is_string()) {
					std::string text = it.value()[i].get<std::string>();
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.3f, 0.8f, 0.3f, 0.8f });
					if (text.empty())
						text = "null";
					ImGui::SameLine();
					ImGui::Text("\"%s\"", text.c_str());
					ImGui::PopStyleColor();
				}
				else if (it.value()[i].is_number()) {
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.8f, 0.3f, 0.3f, 0.8f });
					ImGui::SameLine();
					if (it.value()[i].is_number_float()) {
						ImGui::Text("%.2f", it.value()[i].get<double>());
					}
					else {
						ImGui::Text("%lld", it.value()[i].get<int64_t>());
					}
					ImGui::PopStyleColor();
				}
				else {
					display_json(it.value()[i]);
				}
				ImGui::Unindent();
			}
		}
		else if (it.value().is_string()) {
			std::string text = it.value().get_ref<const std::string&>();
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.3f, 0.8f, 0.3f, 0.8f });

			if (text.empty())
				ImGui::Text("\"\"");
			else if (is_jwt(text))
			{
				ImGui::Indent(20);
				ImGui::NewLine();
				display_json(jwt_to_json(text));
				ImGui::Unindent(20);
			}
			else
				ImGui::Text("\"%s\"", text.c_str());
				ImGui::PopStyleColor();
		}
		else if (it.value().is_boolean()) {
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.3f, 0.3f, 0.8f, 0.8f });
			ImGui::Text("%s", it.value().get<bool>() ? "true" : "false");
			ImGui::PopStyleColor();
		}
		else if (it.value().is_number()) {
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.8f, 0.3f, 0.3f, 0.8f });
			if (it.value().is_number_float()) {
				ImGui::Text("%.2f", it.value().get<double>());
			}
			else {
				ImGui::Text("%lld", it.value().get<int64_t>());
			}
			ImGui::PopStyleColor();
		}
		else if (it.value().is_null()) {
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.5f, 0.5f, 0.5f, 0.8f });
			ImGui::Text("null");
			ImGui::PopStyleColor();
		}
		else {
			ImGui::Text("(unknown json type)");
		}
	}
	ImGui::PopStyleColor();
}

HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
	if (!init)
	{
		if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pDevice)))
		{
			pDevice->GetImmediateContext(&pContext);
			DXGI_SWAP_CHAIN_DESC sd;
			pSwapChain->GetDesc(&sd);
			window = sd.OutputWindow;
			ID3D11Texture2D* pBackBuffer;
			pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
			pDevice->CreateRenderTargetView(pBackBuffer, NULL, &mainRenderTargetView);
			pBackBuffer->Release();
			oWndProc = (WNDPROC)SetWindowLongPtr(window, GWLP_WNDPROC, (LONG_PTR)WndProc);
			InitImGui();
			init = true;
		}

		else
			return oPresent(pSwapChain, SyncInterval, Flags);
	}


	if (Events.iswindowactive != false)
	Events.iswindowactive = true;

	if (Events.iswindowactive == true)
	{
		//Events.isauthed = true;
		if (Events.isauthed == true) {
			//std::cout << "Belcher" << std::endl;
			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.70196, 0.70196, 0.70196, 1.f });
			ImGui::Begin(std::string(Events.MOTD).c_str(), &Events.iswindowactive, ImGuiWindowFlags_NoCollapse);

			ImGui::PopStyleColor();
			ImGui::SetWindowSize(ImVec2{ 800, 520 });
			ImGuiStyle* style = &ImGui::GetStyle();

			style->WindowMinSize = ImVec2(800, 520);
			style->WindowTitleAlign = ImVec2(0.5, 0.5);
			style->WindowPadding = ImVec2(15, 15);
			style->WindowRounding = 5.0f;
			style->FramePadding = ImVec2(8, 6);
			style->FrameRounding = 4.0f;
			style->ItemSpacing = ImVec2(12, 8);
			style->ItemInnerSpacing = ImVec2(8, 6);
			style->IndentSpacing = 25.0f;
			style->ScrollbarSize = 10.0f;
			style->ScrollbarRounding = 9.0f;
			style->GrabMinSize = 5.0f;
			style->GrabRounding = 3.0f;

			style->Colors[ImGuiCol_Text] = ImVec4(0.70196f, 0.70196f, 0.70196f, 1.00f);
			style->Colors[ImGuiCol_TextDisabled] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
			style->Colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
			style->Colors[ImGuiCol_ChildBg] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
			style->Colors[ImGuiCol_PopupBg] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
			style->Colors[ImGuiCol_Border] = ImVec4(0.80f, 0.80f, 0.83f, 0.00f);
			style->Colors[ImGuiCol_BorderShadow] = ImVec4(0.92f, 0.91f, 0.88f, 0.00f);
			style->Colors[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
			style->Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
			style->Colors[ImGuiCol_FrameBgActive] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
			style->Colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
			style->Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(1.00f, 0.98f, 0.95f, 0.75f);
			style->Colors[ImGuiCol_TitleBgActive] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
			style->Colors[ImGuiCol_MenuBarBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
			style->Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
			style->Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
			style->Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
			style->Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
			style->Colors[ImGuiCol_PopupBg] = ImVec4(0.19f, 0.18f, 0.21f, 1.00f);
			style->Colors[ImGuiCol_CheckMark] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
			style->Colors[ImGuiCol_SliderGrab] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
			style->Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
			style->Colors[ImGuiCol_Button] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
			style->Colors[ImGuiCol_ButtonHovered] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
			style->Colors[ImGuiCol_ButtonActive] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
			style->Colors[ImGuiCol_Header] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
			style->Colors[ImGuiCol_HeaderHovered] = ImVec4(0.56f, 0.56f, 0.58f, 0.20f);
			style->Colors[ImGuiCol_HeaderActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
			style->Colors[ImGuiCol_Separator] = ImVec4(0.40196, 0.40196, 0.40196, 1.00f);
			style->Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
			style->Colors[ImGuiCol_SeparatorActive] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
			style->Colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
			style->Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
			style->Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
			style->Colors[ImGuiCol_PlotLines] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
			style->Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
			style->Colors[ImGuiCol_PlotHistogram] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
			style->Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
			style->Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.25f, 1.00f, 0.00f, 0.43f);
			style->Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(1.00f, 0.98f, 0.95f, 0.73f);
			style->Colors[ImGuiCol_Tab] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
			style->Colors[ImGuiCol_TabHovered] = ImVec4(0.26f, 0.26f, 0.28f, 0.50f);
			style->Colors[ImGuiCol_TabActive] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
			static auto tab = 1; 

			static ImVec4 active = ImVec4(0.20f, 0.19f, 0.22f, 1.00f);
			static ImVec4 inactive = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);

			const auto tabSize = ImVec2(86, 25);
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 1 ? active : inactive);
			if (ImGui::Button("Items", tabSize)) { tab = 1; }
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 0 ? active : inactive);
			if (ImGui::Button("Titles", tabSize)) { tab = 0; }
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 2 ? active : inactive);
			if (ImGui::Button("Custom UI", tabSize)) { tab = 2; }
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 3 ? active : inactive);
			if (ImGui::Button("Colors", tabSize)) { tab = 3; }
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 4 ? active : inactive);
			if (ImGui::Button("Persona", tabSize)) { tab = 4; }
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 5 ? active : inactive);
			if (ImGui::Button("Rank", tabSize)) { tab = 5; }
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 6 ? active : inactive);
			if (ImGui::Button("Misc", tabSize)) { tab = 6; }
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, tab == 7 ? active : inactive);
			if (ImGui::Button("Psynet", tabSize)) { tab = 7; }

			const auto avail = ImGui::GetContentRegionAvail();
			const auto offset = 195.f;

			switch (tab)
			{
			case 0:
			{
				ImGui::BeginGroup();
				ImGui::BeginChild(1, { (avail.x - 8) * 0.5f, (avail.y * 0.79f) }, true);

				// Start

				ImGui::Text("Custom Titles:");

				ImGui::Checkbox("Toggle Title", &Events.setcustomtitle);
				ImGui::SameLine();
				ImGui::InputText("Title Text", (char*)Events.titletext.c_str(), sizeof(std::string));

				ImGui::Checkbox("Rainbow     ", &Events.RGBTitle);
				ImGui::SameLine();
				if (ImGui::Button("Refresh the title on your banner")) { Events.resettitle = true; }

				if (ImGui::CollapsingHeader("Colors")) {
					ImGui::Indent(15);
					ImGui::Spacing();

					ImGui::PushItemWidth(width);
					ImGui::ColorPicker3("Title Color", Events.titlecolors);
					ImGui::SameLine();
					ImGui::ColorPicker3("Title Glow", Events.titleglowcolors);
					ImGui::PopItemWidth();

					ImGui::Unindent();
				}

				// End
				ImGui::EndChild();

				ImGui::BeginChild(2, { (avail.x - 8) * 0.5f, ImGui::GetContentRegionAvail().y  }, true);

				// Start
				ImGui::Text("Paid Title: ");
				ImGui::Checkbox("Display Paid Title", &Events.dopaidcustomtitle);
				ImGui::SameLine();
				if (ImGui::Button("Refresh Payed Title")) { Events.refreshtitle = true; }
				//End

				ImGui::EndChild();
				ImGui::EndGroup();

				ImGui::SameLine();

				ImGui::BeginGroup();
				ImGui::BeginChild(3, { (avail.x - 8) * 0.5f, (avail.y - 8) * 0.189f }, true);
				//Start
				ImGui::Text("Title Spawning:");

				if (ImGui::Button("Spawn All Titles")) { Events.spawntitles = true; }
				ImGui::SameLine();
				if (ImGui::Button("Reset Inventory")) { Events.syncinventory = true; }
				//End
				ImGui::EndChild();

				ImGui::BeginChild(4, { }, true);
				//Start
				ImGui::Text("Individual Spawning:");

				static ImGuiTextFilter titlefilter; titlefilter.Draw("");

				ImGui::SameLine();

				if (ImGui::Button("Spawn Title")) { Events.spawnsingletitle = true; }

				if (ImGui::BeginListBox("", ImVec2{ 435, 205 }))
				{
					for (int n = 0; n < Events.TitlesForImGui.size(); n++)
					{
						const bool IsSelected = (Events.selectedTitleForSpawn.titleid == Events.TitlesForImGui[n].titleid);
						if (Events.TitlesForImGui[n].titletext != "" && Events.TitlesForImGui[n].titletext != "null") {
							ImGui::PushID(n);

							ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(Events.TitlesForImGui[n].titlecolor.R, Events.TitlesForImGui[n].titlecolor.G, Events.TitlesForImGui[n].titlecolor.B, Events.TitlesForImGui[n].titlecolor.A));

							if (titlefilter.PassFilter(Events.TitlesForImGui[n].titletext.c_str()))
							{
								if (ImGui::Selectable(Events.TitlesForImGui[n].titletext.c_str(), &IsSelected, ImGuiSelectableFlags_SelectOnClick))
								{
									Events.selectedTitleForSpawn = Events.TitlesForImGui[n];
								}

								ImGui::PopID();
								ImGui::PopStyleColor();
							}

							if (IsSelected) {
								Events.selectedTitleForSpawn = Events.TitlesForImGui[n];
								SelectableColor(IM_COL32(Events.TitlesForImGui[n].titleglow.R, Events.TitlesForImGui[n].titleglow.G, Events.TitlesForImGui[n].titleglow.B, 30));
								ImGui::SetItemDefaultFocus();
							}
						}
					}	
					ImGui::EndListBox();
				}

				ImGui::Separator();
				if (ImGui::Button("Dump Titles To File")) { 
					Events.dumptitles = true;
				
					TCHAR buffer[MAX_PATH] = { 0 };
					GetModuleFileName(NULL, buffer, MAX_PATH);
					std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
					std::wstring location = std::wstring(buffer).substr(0, pos);
					std::string sloc(location.begin(), location.end());
					std::string finallocation = sloc + "\\Voltage\\titles.json";
					std::wstring stemp = std::wstring(finallocation.begin(), finallocation.end());
					LPCWSTR sw = stemp.c_str();
					ShellExecute(NULL, L"Notepad \"Voltage\\titles.json\"", sw, NULL, NULL, SW_SHOWDEFAULT);
				}
				//End

				ImGui::EndChild();
				ImGui::EndGroup();

			}
			break;
			case 1:
			{
				ImGui::BeginGroup();
				ImGui::BeginChild(1, { (avail.x - 8) * 0.5f, avail.y * 0.7f }, true);
				//start
				ImGui::Text("Individual Items:");

				ImGui::Checkbox("Spawn Painted Set", &Events.spawnpaintedset);
				ImGui::SameLine();
				if (ImGui::Button("Spawn Item(s)")) { Events.spawnitemrn = true; }

				static ImGuiTextFilter items;
				const bool is_input_text_enter_pressed = items.Draw("Item", 247);
				const bool is_input_text_active = ImGui::IsItemActive();
				const bool is_input_text_activated = ImGui::IsItemActivated();

				if (is_input_text_activated)
					ImGui::OpenPopup("##productpopup");

				{
					ImGui::SetNextWindowPos(ImVec2(ImGui::GetItemRectMin().x, ImGui::GetItemRectMax().y));
					ImGui::SetNextWindowSize({ 295, 150 });
					if (ImGui::BeginPopup("##productpopup", ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_ChildWindow))
					{
						for (int i = 0; i < Events.ProductsForImGui.size(); i++)
						{
							std::string Product = Events.ProductsForImGui[i].Label;
							std::string Slot = Events.ProductsForImGui[i].Slot;

							std::string itemslotname;

							if (!Events.ProductsForImGui[i].RequiredProduct.Label.empty())
							{
								itemslotname = itemslotname + Events.ProductsForImGui[i].RequiredProduct.Label + ": ";
							}

							itemslotname = itemslotname + Product + " (" + Slot + ")";

							if (items.PassFilter(Product.c_str()))
							{
								bool isSelected = (i == Events.currentItemid);
								if (ImGui::Selectable(itemslotname.c_str(), isSelected))
								{
									Events.itemId = Events.ProductsForImGui[i].ID;
									Events.currentItemid = Events.ProductsForImGui[i].ID;
									strcpy_s(items.InputBuf, Product.c_str());
									ImGui::CloseCurrentPopup();
								}
								if (isSelected) {
									ImGui::SetItemDefaultFocus();
								}
							}
						}

						if (!is_input_text_active && !is_input_text_activated && !ImGui::IsWindowFocused())
							ImGui::CloseCurrentPopup();

						ImGui::EndPopup();
					}
				}
				if (ImGui::BeginCombo("Paint", Events.PaintsForImGui[Events.paintId].c_str())) {
					for (int i = 0; i < Events.PaintsForImGui.size(); i++) {
						bool isSelected = (i == Events.paintId);
						if (ImGui::Selectable(Events.PaintsForImGui[i].c_str(), isSelected)) {
							Events.paintId = i;
						}
						if (isSelected) {
							ImGui::SetItemDefaultFocus();
						}
					}
					ImGui::EndCombo();
				}
				if (ImGui::BeginCombo("Rarity", Events.QualitiesForImGui[Events.qualityId].c_str())) {
					for (int i = 0; i < Events.QualitiesForImGui.size(); i++) {
						bool isSelected = (i == Events.qualityId);
						if (ImGui::Selectable(Events.QualitiesForImGui[i].c_str(), isSelected)) {
							Events.qualityId = i;
						}
						if (isSelected) {
							ImGui::SetItemDefaultFocus();
						}
					}
					ImGui::EndCombo();
				}
				if (ImGui::BeginCombo("Certification", Events.CertsForImGui[Events.certId].c_str())) {
					for (int i = 0; i < Events.CertsForImGui.size(); i++) {
						bool isSelected = (i == Events.certId);
						if (ImGui::Selectable(Events.CertsForImGui[i].c_str(), isSelected)) {
							Events.certId = i;
						}
						if (isSelected) {
							ImGui::SetItemDefaultFocus();
						}
					}
					ImGui::EndCombo();
				}
				ImGui::InputInt("Quantity", &Events.quantity);
				ImGui::Text(" ");
				if (ImGui::Button("Reset Inventory")) { Events.syncinventory = true; }
				//end
				ImGui::EndChild();

				ImGui::BeginChild(2, { (avail.x - 8) * 0.5f, ImGui::GetContentRegionAvail().y }, true);
				//start
				ImGui::Text("Settings:");

				ImGui::Checkbox("Notify", &Events.notifyspawn);
				ImGui::SameLine();
				ImGui::Checkbox("Disable Inventory Syncing", &Events.disableinventorysyncs);

				ImGui::Separator();
				if (ImGui::Button("Open Voltage Folder")) { 
					TCHAR buffer[MAX_PATH] = { 0 };
					GetModuleFileName(NULL, buffer, MAX_PATH);
					std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
					std::wstring location = std::wstring(buffer).substr(0, pos);
					std::string sloc(location.begin(), location.end());
					std::string finallocation = sloc + "\\Voltage";
					std::wstring stemp = std::wstring(finallocation.begin(), finallocation.end());
					LPCWSTR sw = stemp.c_str();
					ShellExecute(NULL, L"open", sw, NULL, NULL, SW_SHOWDEFAULT);
				}
				ImGui::SameLine();
				if (ImGui::Button("Save Item List To File"))
				{
					Events.dumpitems = true;
				}
				//end
				ImGui::EndChild();
				ImGui::EndGroup();

				ImGui::SameLine();

				ImGui::BeginGroup();
				ImGui::BeginChild(3, { (avail.x - 8) * 0.5f, ImGui::GetContentRegionAvail().y }, true);
				//start
				ImGui::Text("Item Sets:");

				if (ImGui::Button("Spawn All")) { Events.spawneveryitem = true; }
				if (ImGui::Button("Spawn All (Painted)")) { Events.spawneveryitempainted = true; }

				ImGui::Separator();

				if (ImGui::CollapsingHeader("Quality Based Sets")) {
					ImGui::Indent(15);
					if (ImGui::Button("Spawn Commons")) { Events.EPQ_Common = true; }
					if (ImGui::Button("Spawn Uncommons")) { Events.EPQ_Uncommon = true; }
					if (ImGui::Button("Spawn Rares")) { Events.EPQ_Rare = true; }
					if (ImGui::Button("Spawn Very Rares")) { Events.EPQ_VeryRare = true; }
					if (ImGui::Button("Spawn Imports")) { Events.EPQ_Import = true; }
					if (ImGui::Button("Spawn Exotics")) { Events.EPQ_Exotic = true; }
					if (ImGui::Button("Spawn Black Markets")) { Events.EPQ_BlackMarket = true; }
					if (ImGui::Button("Spawn Premiums")) { Events.EPQ_Premium = true; }
					if (ImGui::Button("Spawn Limiteds")) { Events.EPQ_Limited = true; }
					if (ImGui::Button("Spawn Legacys")) { Events.EPQ_Legacy = true; }
					ImGui::Unindent();
				}

				if (ImGui::CollapsingHeader("Slot Based Sets")) {
					ImGui::Indent(15);
					for (SSlotData& slotData : Events.slotlists) {
						std::string title("Spawn " + slotData.SlotLabel + std::string(Instances.ends_with(slotData.SlotLabel, "s") == true ? "" : "s"));
						if (Instances.ends_with(title, "ys"))
							Instances.ReplaceString(title, "ys", "ies");
						if (Instances.ends_with(title, "hs"))
							Instances.ReplaceString(title, "hs", "hes");
						if (slotData.Products.size() > 1)
							if (ImGui::Button(title.c_str())) {
								for (SProductData& product : slotData.Products)
								{
									if (Events.spawnpaintedset) {
										for (int i = 0; i < 19; i++) {
											std::string paintIndex = std::to_string(i);
											product.Attributes.push_back({ "Painted", paintIndex });
											Events.productsToSpawn.push_back(product);
											product.Attributes.clear();
										}
									} 
									else 
									{
										Events.productsToSpawn.push_back(product);
									}
								}
								
								Events.multiSpawnProds = true;
							}
					}
					ImGui::Unindent();
				}

				if (ImGui::CollapsingHeader("Miscellaneous Sets")) {
					ImGui::Indent(15);
					if (ImGui::Button("Spawn Alpha Items")) { Events.alphaset = true; }
					if (ImGui::Button("Spawn Hacker Items")) { Events.hackerset = true; }
					ImGui::Unindent();
				}

				try {
					for (json SetCategory : SetCategories)
					{
						if (ImGui::CollapsingHeader(SetCategory["Label"].get<std::string>().c_str()))
						{
							ImGui::Indent(15);

							for (json ItemSet : SetCategory["ItemSets"])
							{
								if (ImGui::Button(("Spawn " + ItemSet["Label"].get<std::string>()).c_str()))
								{
									for (json product : ItemSet["Products"])
									{
										SProductData sproduct;
										if (!product["ID"].is_null())
											sproduct.ID = product["ID"].get<int>();
										if (!product["Series"].is_null())
											sproduct.Series = product["Series"].get<int>();
										if (!product["TradeHold"].is_null())
											sproduct.TradeHold = product["TradeHold"].get<int>();
										if (!product["Attributes"].is_null());
										for (json attribute : product["Attributes"])
										{
											sproduct.Attributes.push_back({ attribute["Key"].get<std::string>(), attribute["Value"].get<std::string>() });
										}

										Events.productsToSpawn.push_back(sproduct);
									}

									Events.multiSpawnProds = true;
								}
							}

							ImGui::Unindent();
						}
					}
				}

				catch (json::exception& e)
				{
					Console.Error(e.what());
				}

				ImGui::Separator();

				//ImGui::BeginChild(1, { (avail.x - 8) * 0.5f, avail.y * 0.7f }, true);
				//start
				ImGui::Text("Spawn Currencies:");

				if (ImGui::Button("Spawn Currency(s)")) { Events.spawncredsrn = true; }
				ImGui::SetNextItemWidth(200);
				ImGui::InputInt("Quantity", &Events.credsquantity);	
				ImGui::SetNextItemWidth(200);
				ImGui::InputInt("Currency ID", &Events.currencyid);
				ImGui::Text(" ");
				if (ImGui::Button("Reset Wallet")) { Events.syncwallet = true; }
				//end
				//ImGui::EndChild();

				//end
				ImGui::EndChild();
				ImGui::EndGroup();
			}
			break;
			case 2:
			{
				ImGui::BeginChild(1, { }, true);
				//start
				if (ImGui::CollapsingHeader("Custom Modals")) {
					ImGui::Indent(15);
					// Enum selector for the EModalType
					const char* items[] = { "Fun", "Ban", "Warning" };
					static int item_current = static_cast<int>(Events.createdmodaltype);  // Assuming createdmodaltype is globally accessible
					ImGui::Combo("Modal Type", &item_current, items, IM_ARRAYSIZE(items));
					Events.createdmodaltype = static_cast<EModalType>(item_current);

					// Checkbox for the createmodalrn
					if (ImGui::Button("Create Model")) { Events.createmodalrn = true; }

					// Color picker for the modalcolor
					static ImVec4 color = ImVec4(Events.custommodalcolor.R / 255.f, Events.custommodalcolor.G / 255.f, Events.custommodalcolor.B / 255.f, Events.custommodalcolor.A / 255.f);
					if (ImGui::ColorEdit4("Modal Color", (float*)&color))
					{
						Events.custommodalcolor.R = static_cast<uint8_t>(color.x * 255.f);
						Events.custommodalcolor.G = static_cast<uint8_t>(color.y * 255.f);
						Events.custommodalcolor.B = static_cast<uint8_t>(color.z * 255.f);
						Events.custommodalcolor.A = static_cast<uint8_t>(color.w * 255.f);
					}

					// Input text for the modaltitle
					static char title[256];
					strcpy(title, Events.custommodaltitle.c_str());
					if (ImGui::InputText("Modal Title", title, IM_ARRAYSIZE(title)))
					{
						Events.custommodaltitle = std::string(title);
					}

					// Input text for the modalbody
					static char body[256];
					strcpy(body, Events.custommodalbody.c_str());
					if (ImGui::InputText("Modal Body", body, IM_ARRAYSIZE(body)))
					{
						Events.custommodalbody = std::string(body);
					}

					if (item_current == 1) {
						ImGui::Separator();
						// Dynamic list for the banCitations
						for (int i = 0; i < Events.banCitations.size(); i++) {
							ImGui::PushID(i);

							char buf[64];
							strncpy(buf, Events.banCitations[i].c_str(), sizeof(buf));
							buf[sizeof(buf) - 1] = 0;
							if (ImGui::InputText("##valuecitation", buf, sizeof(buf))) {
								Events.banCitations[i] = buf;
							}

							// Allow removing this element
							if (ImGui::Button("Remove Citation")) {
								Events.banCitations.erase(Events.banCitations.begin() + i);
							}

							ImGui::PopID();
						}

						// Add new string to vector
						static char buf[64] = "";
						ImGui::InputText("##addcitation", buf, sizeof(buf));
						if (ImGui::Button("Add Citation")) {
							Events.banCitations.push_back(buf);
							buf[0] = '\0';  // Clear input text
						}

						ImGui::Separator();
					}

					// Dynamic list for the modalbuttons
					for (size_t i = 0; i < Events.modalbuttons.size(); i++)
					{
						ImGui::PushID(i + 2);

						char buf[64];
						strncpy(buf, Events.modalbuttons[i].c_str(), sizeof(buf));
						buf[sizeof(buf) - 1] = 0;
						if (ImGui::InputText("##valuebutton", buf, sizeof(buf))) {
							Events.modalbuttons[i] = buf;
						}

						// Allow removing this element
						if (ImGui::Button("Remove Button")) {
							Events.modalbuttons.erase(Events.modalbuttons.begin() + i);
						}

						ImGui::PopID();
					}

					// Add new string to vector
					static char buf[64] = "";
					ImGui::InputText("##addmodalbuttons", buf, sizeof(buf));
					if (ImGui::Button("Add Button")) {
						Events.modalbuttons.push_back(buf);
						buf[0] = '\0';  // Clear input text
					}
					ImGui::Unindent(15);
				}

				if (ImGui::CollapsingHeader("UI Config")) {
					ImGui::Indent(15);
					ImGui::Checkbox("Crate Animations", &Events.crateanimations);
					
					static const char* items[] = { "Default", "Utopia Snow", "Haunted Station", "Beach", "Beach Night", "Halloween", "China",
								"Park Day", "Music", "Throwback Hockey", "Circuit", "Outlaw", "Arc", "Park Snowy",
								"Tokyo Toon", "Utopia Lux", "Street", "Fire And Ice", "Oasis", "Vida", "Tokyo Hax", "Euro Dusk", "Aqua Grass"};

					static int item_current = Events.mainmenubackground;

					ImGui::Combo("Main Menu Background", &item_current, items, IM_ARRAYSIZE(items));
					EMainMenuBackground currentSelection = static_cast<EMainMenuBackground>(item_current);

					Events.mainmenubackground = (uint8_t)currentSelection;

					if (ImGui::Button("Update Menu Background")) {
						Events.needtochangemenubg = true;
					}
					ImGui::Unindent(15);
				}

				ImGui::Separator();
				if (ImGui::Button("Open Textures Folder")) { 
					TCHAR buffer[MAX_PATH] = { 0 };
					GetModuleFileName(NULL, buffer, MAX_PATH);
					std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
					std::wstring location = std::wstring(buffer).substr(0, pos);
					std::string sloc(location.begin(), location.end());
					std::string finallocation = sloc + "\\Voltage\\Textures";
					std::wstring stemp = std::wstring(finallocation.begin(), finallocation.end());
					LPCWSTR sw = stemp.c_str();
					ShellExecute(NULL, L"open", sw, NULL, NULL, SW_SHOWDEFAULT);
				}
				ImGui::SameLine();
				if (ImGui::Button("Refresh Textures")) { Events.refreshtextures = true; }
				//end
				ImGui::EndChild();
			}
			break;
			case 3:
			{
				ImGui::BeginChild(1, { (avail.x - 8) * 0.5f, ImGui::GetContentRegionAvail().y }, true);
				//start
				ImGui::Text("Car Colors:");

				ImGui::Checkbox("Enable Custom Trim", &Events.custompainttrim);
				ImGui::Checkbox("Rainbow Trim", &Events.custompainttrimrgb);

				if (ImGui::CollapsingHeader("Trim Color")) {
					ImGui::Indent(15);
					ImGui::PushItemWidth(width);
					ImGui::ColorPicker3("##Trim Color", Events.customtrimcolors);
					ImGui::PopItemWidth();
					ImGui::Unindent();
				}

				ImGui::Text("");
				ImGui::Text("");

				ImGui::Checkbox("Enable Custom Headlights", &Events.customheadlights);
				ImGui::Checkbox("Rainbow Headlights", &Events.rainbowheadlights);

				if (ImGui::CollapsingHeader("Headlight Color")) {
					ImGui::Indent(15);
					ImGui::PushItemWidth(width);
					ImGui::ColorPicker3("##Custom Headlight Color", Events.customheadlightcolors);
					ImGui::PopItemWidth();
					ImGui::Unindent();
				}
				//end
				ImGui::EndChild();
				ImGui::SameLine();
				ImGui::BeginGroup();
				ImGui::BeginChild(2, { (avail.x - 8) * 0.5f, avail.y * 0.45f }, true);
				//start
				ImGui::Text("Stadium Colors:");

				ImGui::Checkbox("Rainbow", &Events.rgbteamcolors);
				if (ImGui::CollapsingHeader("Blue Team")) {
					ImGui::Indent(15);
					ImGui::Checkbox("Default Colors", &Events.defaultblueteamcolors);
					ImGui::Checkbox("Custom Blue Colors", &Events.custombluecolors);

					ImGui::PushItemWidth(width);
					ImGui::ColorPicker3("Custom Color", Events.blueteamcolor);
					ImGui::PopItemWidth();
					ImGui::Unindent();
				}
				if (ImGui::CollapsingHeader("Orange Team")) {
					ImGui::Indent(15);
					ImGui::Checkbox("Default Colors", &Events.defaultorangeteamcolors);
					ImGui::Checkbox("Custom Orange Colors", &Events.customorangecolors);

					ImGui::PushItemWidth(width);
					ImGui::ColorPicker3("Custom Color", Events.orangeteamcolor);
					ImGui::PopItemWidth();
					ImGui::Unindent();
				}
				//end
				ImGui::EndChild();
				ImGui::BeginChild(3, { (avail.x - 8) * 0.5f, ImGui::GetContentRegionAvail().y }, true);

				ImGui::Text("Team HUD Colors:");

				ImGui::Checkbox("Rainbow", &Events.GFXrgbteamcolors);
				if (ImGui::CollapsingHeader("Blue Team")) {
					ImGui::Indent(15);
					ImGui::Checkbox("Default Colors", &Events.GFXdefaultblueteamcolors);
					ImGui::Checkbox("Custom Blue Colors", &Events.GFXcustombluecolor);

					ImGui::PushItemWidth(width);
					ImGui::ColorPicker3("Custom Color", Events.GFXcustombluecolors);
					ImGui::PopItemWidth();
					ImGui::Unindent();
				}

				if (ImGui::CollapsingHeader("Orange Team")) {
					ImGui::Indent(15);
					ImGui::Checkbox("Default Colors", &Events.GFXdefaultorangeteamcolors);
					ImGui::Checkbox("Custom Orange Colors", &Events.GFXcustomorangecolor);

					ImGui::PushItemWidth(width);
					ImGui::ColorPicker3("Custom Color", Events.GFXcustomorangecolors);
					ImGui::PopItemWidth();
					ImGui::Unindent();
				}
				//end
				ImGui::EndChild();
				ImGui::EndGroup();
			}
			break;
			case 4:
			{
				ImGui::BeginChild(1, { }, true);
				//start
				ImGui::Checkbox("Ingame Only - Custom Avatar (Avatar.png in the textures folder)", &Events.customavatar);
				ImGui::SameLine();
				if (ImGui::Button("Open Textures Folder")) {
					TCHAR buffer[MAX_PATH] = { 0 };
					GetModuleFileName(NULL, buffer, MAX_PATH);
					std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
					std::wstring location = std::wstring(buffer).substr(0, pos);
					std::string sloc(location.begin(), location.end());
					std::string finallocation = sloc + "\\Voltage\\Textures";
					std::wstring stemp = std::wstring(finallocation.begin(), finallocation.end());
					LPCWSTR sw = stemp.c_str();
					ShellExecute(NULL, L"open", sw, NULL, NULL, SW_SHOWDEFAULT);
				}

				ImGui::Checkbox("Custom Username", &Events.setcustomusername);
				ImGui::SameLine();
				ImGui::InputText("Username", (char*)Events.customusername.c_str(), sizeof(std::string));

				if (ImGui::Button("Clear All Friend Requests")) { Events.needtoclearfriends = true;  }

				if (ImGui::Button("Invite User")) { Events.shouldinvitehomie = true; }
				ImGui::SameLine();
				ImGui::InputText("Steam/Epic ID", (char*)Events.trollingsteamid.c_str(), sizeof(std::string));
				ImGui::Text("User doesn't have to be added");
				//end
				ImGui::EndChild();
			}
			break;
			case 5:
			{
				ImGui::BeginGroup();
				ImGui::BeginChild(1, { (avail.x - 8) * 0.5f, avail.y * 0.5f }, true);
				//start
				ImGui::Text("Rank:");
				static ImGuiTextFilter rankfilter; rankfilter.Draw("");

				if (ImGui::BeginListBox("", ImVec2{ 246, 120 }))
				{
					for (int n = 0; n < IM_ARRAYSIZE(ranklistbox_items); n++) 
					{
						if (rankfilter.PassFilter(Events.PlaylistsForRankEditing[n].c_str()))
						{
							ImGui::PushID(n);
							if (ImGui::Selectable(ranklistbox_items[n]))
								selected_rankitem = n;
							ImGui::PopID();

							if (n == selected_rankitem) 
							{
								SelectableColor(IM_COL32(211, 211, 211, 30));
								ImGui::SetItemDefaultFocus();
							}
						}
					}
					ImGui::EndListBox();
				}

				if (rankDivision > 3)
					rankDivision = 3;
				if (rankDivision < 1)
					rankDivision = 1;
				if (Events.customrankplaylist > 4)
					Events.customrankplaylist = 4;
				if (Events.customrankplaylist < 1)
					Events.customrankplaylist = 1;
				if (Events.seasonalwins > 10)
					Events.seasonalwins = 10;
				if (Events.seasonalwins < 1)
					Events.seasonalwins = 1;
				//end
				ImGui::EndChild();
				ImGui::BeginChild(2, { (avail.x - 8) * 0.5f, ImGui::GetContentRegionAvail().y }, true);
				//start
				ImGui::Text("Playlist:");
				
				static ImGuiTextFilter playlistfilter; playlistfilter.Draw("");
				if (ImGui::BeginListBox("", ImVec2{ 246, 120 }))
				{
					for (int n = 0; n < Events.PlaylistsForRankEditing.size(); n++) 
					{
						if (!Events.PlaylistsForRankEditing[n].find("null")) continue;

						const bool IsSelected = (Events.selectedplaylisttoedit == Events.PlaylistsForRankEditing[n]);

						ImGui::PushID(n);
						if (playlistfilter.PassFilter(Events.PlaylistsForRankEditing[n].c_str()))
						{

							if (ImGui::Selectable(Events.PlaylistsForRankEditing[n].c_str(), &IsSelected, ImGuiSelectableFlags_SelectOnClick)) 
							{
								Events.selectedplaylisttoedit = Events.PlaylistsForRankEditing[n];
							}

							ImGui::PopID();
						}

						if (IsSelected) 
						{
							Events.selectedplaylisttoedit = Events.PlaylistsForRankEditing[n];
							SelectableColor(IM_COL32(211, 211, 211, 30));
							ImGui::SetItemDefaultFocus();
						}
					}
					ImGui::EndListBox();
				}

				//end
				ImGui::EndChild();
				ImGui::EndGroup();

				ImGui::SameLine();

				ImGui::BeginGroup();
				ImGui::BeginChild(3, { (avail.x - 8) * 0.5f, ImGui::GetContentRegionAvail().y }, true);
				//start
				ImGui::SetNextItemWidth(200);
				ImGui::InputInt("MMR", &Events.custommmr);
				ImGui::SetNextItemWidth(100);
				ImGui::InputInt("Division", &Events.customrankplaylist);
				ImGui::SetNextItemWidth(100);
				ImGui::InputInt("Rank Number", &rankDivision);
				/*ImGui::SetNextItemWidth(100);
				ImGui::InputInt("Placement Matches Played", &Events.seasonalwins);*/
				ImGui::Separator();

				if (ImGui::Button("Set Rank")) {
					Events.seasonrewards = selected_rankitem + 1;
					if (selected_rankitem == 0)
						Events.customrank = 1;
					if (selected_rankitem == 1)
						Events.customrank = 4;
					if (selected_rankitem == 2)
						Events.customrank = 7;
					if (selected_rankitem == 3)
						Events.customrank = 10;
					if (selected_rankitem == 4)
						Events.customrank = 13;
					if (selected_rankitem == 5)
						Events.customrank = 16;
					if (selected_rankitem == 6)
						Events.customrank = 19;
					if (selected_rankitem == 7)
						Events.customrank = 22;
					if (selected_rankitem == 8)
						Events.customrank = 69;

					if (rankDivision == 2)
					Events.customrank = Events.customrank + 1;
					if (rankDivision == 3)
						Events.customrank = Events.customrank + 2;
					Events.needtochangerank = true; 
				}
				ImGui::SameLine();
				if (ImGui::Button("Reset Rank(s)")) { Events.needtosyncrank = true; }
				//end
				ImGui::EndChild();
				ImGui::EndGroup();
			}
			break;
			case 6:
			{
				ImGui::BeginChild(1, { }, true);
				//stat
				ImGui::Checkbox("Adblocker (Refresh menu for it to work)", &Events.adblocker);
				ImGui::Checkbox("Display UDP Socket DeltaTime", &Events.displayDeltaTime);
				if (Events.displayDeltaTime) {
					ImGui::SameLine();
					std::string deltatime = ": " + Events.UDPDeltaTime;
					ImGui::Text(deltatime.c_str());
				}
				ImGui::Checkbox("Turntable Main Menu", &Events.turntablemainmenu);
				ImGui::Checkbox("Premium Garage Menu", &Events.premiumgaragemenu);
				ImGui::Checkbox("Give everyone in online match alpha boost", &Events.giveeveryonealphaboost);
				if (ImGui::Button("Invisible Wheels")) { Events.inviswheels++; }
				if (ImGui::Button("Black Car")) { Events.setblackcar = true; }
				if (ImGui::Button("Default Car")) { Events.offblackcar = true; }
				if (ImGui::Button("Crash Party Members")) { Events.crashparty = true; }
				ImGui::Separator();
				if (ImGui::Button("Toggle Scaleform")) Events.disabledscaleform = !Events.disabledscaleform;
				if (ImGui::Button("Invisible Car")) Events.inviscar++;
				if (ImGui::Button("Expire Cache")) Events.refreshConfig = true;
				if (ImGui::Button("Show Datastore Tables")) {
					opendatastorebutton = !opendatastorebutton;
				}
				if (opendatastorebutton == true) {
					LogDatastoreValues();
				}

				ImGui::Text(" ");
				ImGui::SetNextItemWidth(200);
				ImGui::InputInt(" Thumbnail Product ID: ", &Events.avatarToProductThumbnail);
				//ImGui::InputInt("Paint ID", &Events.avatarToProductThumbnailPaint);					
				if (ImGui::Button("Update Displayed Thumbnail")) Events.setAvatarToProductThumbnail = true;
				//if (Events.avatarToProductThumbnail > 0);
				//Instances.ImGuiUTexture(Events.productThumbnailToDisplay);
				if (ImGui::Button("Make Instance Of Every Product Thumbnail")) {
					Events.loopAvatarToProductThumbnail = true;
				}
				ImGui::Separator();
				//ImGui::InputText("", itemToFind, sizeof(std::string));
				//ImGui::SameLine();
				//ImGui::Text(("Found Item ID: " + std::to_string(Instances.SearchProduct(std::string(itemToFind)).ID)).c_str());
				//ImGui::Separator();
				if (ImGui::Button("Clear Cache")) { std::filesystem::remove("Voltage\\config.json"); }
				if (ImGui::Button("Dump Services To File")) {	
					Events.dumpservices = true;
				}
				if (ImGui::Button("Dump Loaded Textures To File")) {
					Events.dumptextures = true;
				}
				if (ImGui::Button("Reload SaveData")) { Events.reloadsavedata = true; }
				ImGui::Separator();
				//ImGui::Text("(W.I.P) TAS Recordings / Keybinds");
				//// Specify the folder path where JSON files are located
				//std::string folderPath = "Voltage/TAS/";

				//// List JSON files in the folder
				//std::vector<std::string> jsonFiles = ListJSONFiles(folderPath);

				//// Start Recording Button
				//if (!Events.recordingTASInput) {
				//	if (ImGui::Button("Start Recording")) {
				//		Events.startTASclip = true;
				//	}
				//}
				//else {
				//	// Stop Recording Button
				//	if (ImGui::Button("Stop Recording")) {
				//		Events.endTASclip = true;
				//	}
				//}

				//ImGui::Separator();

				//// Iterate through JSON files
				//for (size_t i = 0; i < jsonFiles.size(); ++i) {
				//	const std::string& jsonFile = jsonFiles[i];

				//	// Skip the keybinds JSON file itself
				//	if (jsonFile == "keybinds.json") {
				//		continue;
				//	}

				//	ImGui::Text("%s", jsonFile.c_str());

				//	// Display the associated keybind or the set keybind button
				//	if (fileKeybinds.find(jsonFile) != fileKeybinds.end()) {
				//		ImGui::SameLine();
				//		ImGui::Text("Key: %d", fileKeybinds[jsonFile]);
				//	}
				//	else {
				//		ImGui::SameLine();
				//		if (ImGui::Button("Set Keybind")) {
				//			keybindSelectionMode = true;
				//		}
				//	}

				//	// Handle keybind selection mode for this file
				//	if (keybindSelectionMode) {
				//		if (ImGui::IsItemClicked()) {
				//			// Record the file for which the keybind is being set
				//			keybindSelectionMode = false; // Exit keybind selection mode
				//			ImGui::CaptureKeyboardFromApp(true);
				//			ImGui::SetKeyboardFocusHere();
				//		}
				//	}

				//	// Assign the keybind if key is pressed while in keybind selection mode
				//	if (keybindSelectionMode && ImGui::IsKeyPressed(0, false)) {
				//		fileKeybinds[jsonFile] = ImGui::GetIO().KeysDown[0];
				//		keybindSelectionMode = false; // Exit keybind selection mode
				//	}

				//	ImGui::Separator();
				//}


				//ImGui::Separator();
				//if (ImGui::Button("Increase Credits Quantity")) Events.updateQuantity = true;
				//ImGui::InputInt("Increase Credits Amount", &Events.creditsAmount);
				//end
				ImGui::EndChild();
			}
			break;
			case 7:
			{
				ImGui::BeginChild(1, {  }, true);
				//start
				static ImGuiTextFilter psynetfilter; psynetfilter.Draw("");

				if (ImGui::BeginListBox("", { ImGui::GetWindowWidth() - 40, ImGui::GetWindowHeight() - 65 }))
				{
					for (int n = 0; n < Events.psynettrafficlogs.size(); n++) 
					{
						if (Events.psynettrafficheaders[n].empty())
							continue;

						const bool IsSelected = (CurrentItem == n);

						std::string ClipboardText;
						bool copy_to_clipboard = false;

						std::string title = Events.psynettrafficlogs[n];

						if (title == "Response: \"\"")
							continue;

						if (title.find("Request:") != std::string::npos)
						{
							ImGui::PushStyleColor(ImGuiCol_Text, GColorList::Yellow.ImColor());
						}

						if (title.find("Response: ") != std::string::npos)
						{
							ImGui::PushStyleColor(ImGuiCol_Text, GColorList::Green.ImColor());
						}

						if (title.find("Web Request: ") != std::string::npos)
						{
							ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.6f, 0.15f, 0.4f, 1.0f });
						}

						if (title.find("Web Response: ") != std::string::npos)
						{
							ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.6f, 0.2f, 0.6f, 1.0f });
						}

						if (title.find("SERVICE") != std::string::npos)
						{
							Instances.ReplaceString(title, "Response: \"SERVICE", "Service: \"");
							ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.00000, 0.39216, 0.58824, 1.f });
						}

						if (title.find("Not Found") != std::string::npos)
						{
							continue;
						}

						if (psynetfilter.PassFilter(title.c_str()))
						{
							ImGui::PushID(n);
							if (ImGui::CollapsingHeader(title.c_str()))
							{
								ImGui::PopStyleColor();
								ImGui::PushStyleColor(ImGuiCol_Text, ImVec4{ 0.70196, 0.70196, 0.70196, 1.f });

								ImGui::SetNextItemWidth(1);
								if (ImGui::BeginPopupContextWindow())
								{
									copy_to_clipboard = ImGui::Selectable("Copy to Clipboard");
									ImGui::EndPopup();
								}

								if (copy_to_clipboard)
								{
									ClipboardText = title;
								}

								CurrentItem = n;

								ImGui::Indent(20);

								if (ImGui::CollapsingHeader("Header Content"))
								{
									ImGui::Indent(20);

									std::vector<std::string> lines;

									// Split headers into lines
									std::istringstream f(Events.psynettrafficheaders[CurrentItem]);
									std::string line;
									while (std::getline(f, line)) {
										lines.push_back(line);
									}

									// Display lines in ImGui
									for (auto& line : lines) {
										ImGui::Bullet();
										ImGui::Text("%s", line.c_str());
									}

									if (copy_to_clipboard)
									{
										ClipboardText = Events.psynettrafficheaders[CurrentItem];
									}

									ImGui::Unindent(20);
								}

								if (ImGui::CollapsingHeader("Body Content"))
								{
									try
									{
										json bodyjson = json::parse(Events.psynettrafficbodies[CurrentItem]);

										if (title.find("DSR/ClientMessage") != std::string::npos || title.find("Request: \"DSR/RelayToServer") != std::string::npos)
										{
											std::string decode = bodyjson["MessagePayload"].get<std::string>();

											Instances.ReplaceString(decode, "\\\"", "\"");

											bodyjson["MessagePayload"] = json::parse(decode);
										}

										if (title.find("Party/System") != std::string::npos)
										{
											bodyjson["Content"] = json::parse(DecodePartyMessage(Instances.base64_decode(bodyjson["Content"].get<std::string>())));
										}

										if (title.find("Request: \"Party/SendPartyMessage") != std::string::npos)
										{
											bodyjson["Message"] = json::parse(DecodePartyMessage(Instances.base64_decode(bodyjson["Message"].get<std::string>())));
										}

										display_json(bodyjson);

										if (copy_to_clipboard)
											ClipboardText = bodyjson.dump(4);
									}

									catch (json::exception& e) { Console.Error(e.what()); }
									catch (std::bad_alloc& b) { Console.Error(b.what()); }
									catch (std::length_error& e) { Console.Error(e.what()); }
									catch (std::exception& e) { Console.Error(e.what()); }
									catch (SE_Exception& e) { Console.Error(e.getSeMessage()); }
									catch (std::bad_exception& e) { Console.Error(e.what()); }
									catch (curlpp::RuntimeError& e)
									{
										Console.Error(e.what());
									}

									catch (curlpp::LogicError& e)
									{
										Console.Error(e.what());
									}

									catch (std::runtime_error& e)
									{
										Console.Error(e.what());
									}

									catch (curlpp::UnknowException& e)
									{
										Console.Error(e.what());
									}
								}

								ImGui::Unindent(20);
								ImGui::PopStyleColor();
							}
							ImGui::PopID();
						}

						if (copy_to_clipboard && ClipboardText.length() > 0)
						{
							ImGui::SetClipboardText(ClipboardText.c_str());
							ClipboardText.clear();
						}


						if (IsSelected) {
							ImGui::SetItemDefaultFocus();
						}

						if (totalpsynet < Events.totalrequests)
							ImGui::SetScrollHereY();
					}
					ImGui::EndListBox();
				}

				ImGui::EndChild();
				//end
			}
			break;
			}

			ImGui::End();
			ImGui::Render();

			pContext->OMSetRenderTargets(1, &mainRenderTargetView, NULL);
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

			totalpsynet = Events.totalrequests;
		}

	}

	return oPresent(pSwapChain, SyncInterval, Flags);
}

DWORD WINAPI MainThread(LPVOID lpReserved)
{
	bool init_hook = false;
	do
	{
		if (kiero::init(kiero::RenderType::D3D11) == kiero::Status::Success)
		{
			kiero::bind(8, (void**)&oPresent, hkPresent);
			init_hook = true;
		}
	} while (!init_hook);
	return TRUE;
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hMod);
		CreateThread(nullptr, 0, MainThread, hMod, 0, nullptr);
		Core.InitializeThread();
		break;
	case DLL_PROCESS_DETACH:
		kiero::shutdown();
		break;
	}
	return TRUE;
}