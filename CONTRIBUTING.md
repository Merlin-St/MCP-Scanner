# Contributing to MCP Scanner

Thank you for your interest in contributing to MCP Scanner! This document provides guidelines for contributing to this security research tool.

## 🤝 Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code.

## 🚨 Ethical Guidelines

**IMPORTANT**: This is a security research tool. All contributions must:

- Support legitimate security research and authorized testing only
- Include appropriate warnings and disclaimers
- Follow responsible disclosure practices
- Comply with applicable laws and regulations
- Respect rate limits and terms of service

## 🛠️ How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues. When creating a bug report, include:

- **Clear description** of the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, etc.)
- **Log files** (with sensitive data removed)

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:

- **Check existing issues** for similar suggestions
- **Provide clear rationale** for the enhancement
- **Consider security implications** of new features
- **Include implementation details** if possible

### Code Contributions

1. **Fork** the repository
2. **Create a branch** from `main` for your feature
3. **Make your changes** following the style guidelines
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Submit a pull request**

## 📝 Style Guidelines

### Python Code Style

- Follow **PEP 8** style guidelines
- Use **type hints** where appropriate
- Write **docstrings** for all functions and classes
- Keep line length under **100 characters**
- Use **meaningful variable names**

### Documentation Style

- Use **clear, concise language**
- Include **code examples** where helpful
- Add **security warnings** for sensitive features
- Keep **formatting consistent**

### Commit Messages

Use clear commit messages:
```
Add comprehensive Shodan filter for MCP detection

- Added 15 new search patterns for MCP servers
- Improved detection accuracy by 25%
- Updated documentation with new filter explanations
```

## 🧪 Testing

- **Test thoroughly** on multiple platforms
- **Include edge cases** in testing
- **Verify security implications** of changes
- **Check rate limiting** behavior
- **Test with various MCP server implementations**

## 📋 Pull Request Process

1. **Update documentation** for any new features
2. **Add tests** for new functionality
3. **Ensure all tests pass**
4. **Update version numbers** if applicable
5. **Get approval** from maintainers

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security enhancement

## Testing
- [ ] Tested on multiple platforms
- [ ] Added/updated tests
- [ ] Verified security implications
- [ ] Checked rate limiting behavior

## Security Considerations
- [ ] No new security vulnerabilities introduced
- [ ] Appropriate warnings/disclaimers added
- [ ] Follows ethical research practices
```

## 🔒 Security Vulnerability Reporting

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email security concerns privately
2. Provide detailed description
3. Include proof of concept if applicable
4. Allow reasonable time for response

## 📚 Development Setup

```bash
# Clone your fork
git clone https://github.com/knostic/MCP-Scanner.git
cd MCP-Scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy
```

## 🎯 Priority Areas

We especially welcome contributions in:

- **New MCP detection patterns**
- **Additional transport protocols**
- **Performance optimizations**
- **Cross-platform compatibility** 
- **Documentation improvements**
- **Security enhancements**

## ❓ Questions?

- Check existing **issues** and **discussions**
- Review the **documentation**
- Contact maintainers if needed

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Remember**: This tool is for legitimate security research only. All contributions must support ethical and legal use cases. 