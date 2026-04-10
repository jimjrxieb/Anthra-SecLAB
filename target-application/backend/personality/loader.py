"""
Personality Loader
Dynamically loads personality configuration from markdown files
"""

from pathlib import Path
from typing import Dict, Optional
import re


class PersonalityLoader:
    """Load and parse personality configuration from markdown files"""

    def __init__(self, personality_dir: Optional[Path] = None):
        if personality_dir is None:
            personality_dir = Path(__file__).parent
        self.personality_dir = Path(personality_dir)
        self.core_file = self.personality_dir / "jade_core.md"
        self.interview_file = self.personality_dir / "interview_responses.md"

    def load_core_personality(self) -> Dict[str, str]:
        """Load core personality traits from jade_core.md"""
        if not self.core_file.exists():
            return self._get_default_personality()

        with open(self.core_file, 'r', encoding='utf-8') as f:
            content = f.read()

        personality = {
            "name": self._extract_field(content, "Name"),
            "role": self._extract_field(content, "Role"),
            "expertise": self._extract_field(content, "Expertise"),
            "traits": self._extract_section(content, "Personality Traits"),
            "speaking_style": self._extract_section(content, "Speaking Style"),
            "key_messages": self._extract_section(content, "Key Messages to Emphasize"),
            "technical_deepdive": self._extract_section(content, "Technical Deep-Dive Responses"),
        }

        return personality

    def load_interview_responses(self) -> str:
        """Load interview responses from interview_responses.md"""
        if not self.interview_file.exists():
            return ""

        with open(self.interview_file, 'r', encoding='utf-8') as f:
            return f.read()

    def build_system_prompt(self) -> str:
        """Build complete system prompt from personality files"""
        personality = self.load_core_personality()

        # Build system prompt from personality data
        prompt = f"""You are {personality['name']}, {personality['role']}.

PERSONALITY:
{personality['traits']}

SPEAKING STYLE:
{personality['speaking_style']}

EXPERTISE: {personality['expertise']}

KEY MESSAGES:
{personality['key_messages']}

TECHNICAL KNOWLEDGE (Use this information when answering technical questions):
{personality['technical_deepdive']}

TONE: {self._extract_tone(personality)}

IMPORTANT:
- NO roleplay actions (*smiles*, *leans in*, etc.)
- Focus on facts, technical details, and specific examples
- Professional and direct communication
- Answer questions thoroughly without theatrical embellishment
- When asked about Jimmie's DevSecOps experience, use the ACCURATE information from Technical Knowledge above
- NEVER make up or hallucinate certifications, years of experience, or work history"""

        return prompt.strip()

    def _extract_field(self, content: str, field_name: str) -> str:
        """Extract a field value (e.g., **Name**: value)"""
        pattern = rf'\*\*{field_name}\*\*:\s*(.+?)(?:\n|$)'
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _extract_section(self, content: str, section_title: str) -> str:
        """Extract a markdown section by title"""
        # Find section header
        pattern = rf'##\s+{re.escape(section_title)}\s*\n(.*?)(?=\n##|\Z)'
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)

        if match:
            section_content = match.group(1).strip()
            # Clean up markdown formatting for system prompt
            section_content = re.sub(r'\*\*(.+?)\*\*:', r'\1:', section_content)
            return section_content

        return ""

    def _extract_tone(self, personality: Dict[str, str]) -> str:
        """Extract tone description from speaking style"""
        tone_match = re.search(r'Tone[:\-]\s*(.+?)(?:\n|$)',
                               personality['speaking_style'],
                               re.IGNORECASE)
        if tone_match:
            return tone_match.group(1).strip()
        return "Warm, professional, and naturally engaging"

    def _get_default_personality(self) -> Dict[str, str]:
        """Fallback personality if files don't exist"""
        return {
            "name": "Sheyla",
            "role": "AI portfolio assistant representing Jimmie Coleman's work",
            "expertise": "DevSecOps, AI/ML, LinkOps AI-BOX Technology",
            "traits": "Professional yet warm, detail-oriented, technically knowledgeable",
            "speaking_style": "Confident, engaging, with a touch of southern charm",
            "key_messages": "Jimmie solves real business problems with practical AI solutions",
            "technical_deepdive": "Jimmie has 1.5 years of self-taught DevSecOps experience. He holds CKA and CompTIA Security+ certifications.",
        }


# Singleton instance
_loader = None

def get_personality_loader() -> PersonalityLoader:
    """Get or create personality loader instance"""
    global _loader
    if _loader is None:
        _loader = PersonalityLoader()
    return _loader


def load_system_prompt() -> str:
    """Load system prompt from personality files"""
    loader = get_personality_loader()
    return loader.build_system_prompt()
