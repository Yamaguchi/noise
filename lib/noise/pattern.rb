# frozen_string_literal: true

module Noise
  module Token
    E = 'e'
    S = 's'
    EE = 'ee'
    ES = 'es'
    SE = 'se'
    SS = 'ss'
    PSK = 'psk'
  end

  class Pattern
    attr_reader :one_way, :tokens

    def self.create(name)
      class_name = "Noise::Pattern#{name}"
      klass = Object.const_get(class_name)
      klass.new
    end

    def initialize
      @pre_messages = [[], []]
      @tokens = []
      @name = ''
      @one_way = false
      @psk_count = 0
    end

    # initiator [Boolean]
    def required_keypairs(initiator)
      required = []
      if initiator
        required << :s if ['K', 'X', 'I'].include?(@name[0])
        required << :rs if @one_way || @name[1] == 'K'
      else
        required << :rs if @name[0] == 'K'
        required << :s if @one_way || ['K', 'X'].include?(@name[1])
      end
      required
    end

    def initiator_pre_messages
      @pre_messages[0].dup
    end

    def responder_pre_messages
      @pre_messages[1].dup
    end
  end

  class OneWayPattern < Pattern
    def initialize
      super
      @one_way = true
    end
  end

  class PatternN < OneWayPattern
    def initialize
      super
      @name = 'N'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES]]
    end
  end

  class PatternK < OneWayPattern
    def initialize
      super
      @name = 'K'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::SS]]
    end
  end

  class PatternX < OneWayPattern
    def initialize
      super
      @name = 'X'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::S, Token::SS]]
    end
  end

  class PatternNN < Pattern
    def initialize
      super
      @name = 'NN'
      @pre_messages = []
      @tokens = [[Token::E], [Token::E, Token::EE]]
    end
  end

  class PatternKN < Pattern
    def initialize
      super
      @name = 'KN'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternNK < Pattern
    def initialize
      super
      @name = 'NK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE]]
    end
  end

  class PatternKK < Pattern
    def initialize
      super
      @name = 'KK'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::SS], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternNX < Pattern
    def initialize
      super
      @name = 'NX'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES]]
    end
  end

  class PatternKX < Pattern
    def initialize
      super
      @name = 'KX'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE, Token::S, Token::ES]]
    end
  end

  class PatternXN < Pattern
    def initialize
      super
      @name = 'XN'
      @tokens = [[Token::E], [Token::E, Token::EE], [Token::S, Token::SE]]
    end
  end

  class PatternIN < Pattern
    def initialize
      super
      @name = 'IN'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternXK < Pattern
    def initialize
      super
      @name = 'XK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE], [Token::S, Token::SE]]
    end
  end

  class PatternIK < Pattern
    def initialize
      super
      @name = 'IK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::S, Token::SS], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternXX < Pattern
    def initialize
      super
      @name = 'XX'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES], [Token::S, Token::SE]]
    end
  end

  class PatternIX < Pattern
    def initialize
      super
      @name = 'IX'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE, Token::S, Token::ES]]
    end
  end
end
    #
    # def has_pre_messages(self):
    #     return any(map(lambda x: len(x) > 0, self.pre_messages))
    #
    # def get_initiator_pre_messages(self) -> list:
    #     return self.pre_messages[0].copy()
    #
    # def get_responder_pre_messages(self) -> list:
    #     return self.pre_messages[1].copy()
    #
    # def apply_pattern_modifiers(self, modifiers: List[str]) -> None:
    #     # Applies given pattern modifiers to self.tokens of the Pattern instance.
    #     for modifier in modifiers:
    #         if modifier.startswith('psk'):
    #             try:
    #                 index = int(modifier.replace('psk', '', 1))
    #             except ValueError:
    #                 raise ValueError('Improper psk modifier {}'.format(modifier))
    #
    #             if index // 2 > len(self.tokens):
    #                 raise ValueError('Modifier {} cannot be applied - pattern has not enough messages'.format(modifier))
    #
    #             # Add TOKEN_PSK in the correct place in the correct message
    #             if index == 0:  # if 0, insert at the beginning of first message
    #                 self.tokens[0].insert(0, TOKEN_PSK)
    #             else:  # if bigger than zero, append at the end of first, second etc.
    #                 self.tokens[index - 1].append(TOKEN_PSK)
    #             self.psk_count += 1
    #
    #         elif modifier == 'fallback':
    #             raise NotImplementedError  # TODO implement
    #
    #         else:
    #             raise ValueError('Unknown pattern modifier {}'.format(modifier))
