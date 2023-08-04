#include "imgui_extensions.h"

namespace ImExtensions
{
	void ToggleButton(const char* str_id, bool* v)
	{
		ImVec2 p = ImGui::GetCursorScreenPos();
		ImDrawList* draw_list = ImGui::GetWindowDrawList();

		float height = ImGui::GetFrameHeight();
		float width = height * 1.55f;
		float radius = height * 0.50f;

		ImGui::InvisibleButton(str_id, ImVec2(width, height));
		if (ImGui::IsItemClicked())
			*v = !*v;

		float t = *v ? 1.0f : 0.0f;

		ImGuiContext& g = *GImGui;
		float ANIM_SPEED = 0.08f;
		if (g.LastActiveId == g.CurrentWindow->GetID(str_id))// && g.LastActiveIdTimer < ANIM_SPEED)
		{
			float t_anim = ImSaturate(g.LastActiveIdTimer / ANIM_SPEED);
			t = *v ? (t_anim) : (1.0f - t_anim);
		}

		ImU32 col_bg;
		if (ImGui::IsItemHovered())
			col_bg = ImGui::GetColorU32(ImLerp(ImVec4(0.78f, 0.78f, 0.78f, 1.0f), ImVec4(0.64f, 0.83f, 0.34f, 1.0f), t));
		else
			col_bg = ImGui::GetColorU32(ImLerp(ImVec4(0.85f, 0.85f, 0.85f, 1.0f), ImVec4(0.56f, 0.83f, 0.26f, 1.0f), t));

		draw_list->AddRectFilled(p, ImVec2(p.x + width, p.y + height), col_bg, height * 0.5f);
		draw_list->AddCircleFilled(ImVec2(p.x + radius + t * (width - radius * 2.0f), p.y + radius), radius - 1.5f, IM_COL32(255, 255, 255, 255));

		ImGui::SameLine();
		ImGui::Text(str_id);
	}

	int32_t Stricmp(const char* s1, const char* s2)
	{
		int32_t d;

		while ((d = toupper(*s2) - toupper(*s1)) == 0 && *s1)
		{
			s1++;
			s2++;
		}

		return d;
	}

	int32_t Strnicmp(const char* s1, const char* s2, int32_t n)
	{
		int32_t d = 0;

		while (n > 0 && (d = toupper(*s2) - toupper(*s1)) == 0 && *s1)
		{
			s1++;
			s2++;
			n--;
		}

		return d;
	}

	char* StrCpy(const char* s)
	{
		IM_ASSERT(s);
		size_t length = strlen(s) + 1;
		void* buffer = malloc(length);
		IM_ASSERT(buffer);
		memcpy_s(buffer, length, s, length);
		return reinterpret_cast<char*>(buffer);
	}

	void Strtrim(char* s)
	{
		char* strEnd = s + strlen(s);

		while (strEnd > s && strEnd[-1] == ' ')
		{
			strEnd--;
			*strEnd = 0;
		}
	}

	void TextColored(const char* text, const ImVec4& textColor)
	{
		ImGui::PushStyleColor(ImGuiCol_Text, textColor);
		ImGui::TextEx(text);
		ImGui::PopStyleColor();
	}

	void TextStyled(const char* text, const ImVec4& textColor, ImFont* textFont)
	{
		if (textFont) { ImGui::PushFont(textFont); }
		ImGui::PushStyleColor(ImGuiCol_Text, textColor);
		ImGui::TextEx(text);
		ImGui::PopStyleColor();
		if (textFont) { ImGui::PopFont(); }
	}

	void HelpMarker(const char* desc, float posScale)
	{
		ImGui::TextDisabled("(?)");

		if (ImGui::IsItemHovered())
		{
			ImGui::BeginTooltip();
			ImGui::PushTextWrapPos(ImGui::GetFontSize() * posScale);
			ImGui::TextUnformatted(desc);
			ImGui::PopTextWrapPos();
			ImGui::EndTooltip();
		}
	}
}