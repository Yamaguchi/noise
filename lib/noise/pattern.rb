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
    attr_reader :tokens, :modifiers, :psk_count

    def self.create(name)
      pattern_set = name.scan(/([A-Z1]+)([^A-Z]*)/)&.first
      pattern = pattern_set&.first
      modifiers = pattern_set[1].split('+')
      class_name = "Noise::Pattern#{pattern}"
      klass = Object.const_get(class_name)
      klass.new(modifiers)
    end

    def initialize(modifiers)
      @pre_messages = [[], []]
      @tokens = []
      @name = ''
      @psk_count = 0
      @modifiers = modifiers
    end

    def apply_pattern_modifiers
      @modifiers.each do |modifier|
        if modifier.start_with?('psk')
          index = modifier.gsub(/psk/, '').to_i
          raise Noise::Exceptions::PSKValueError if index / 2 > @tokens.size

          if index.zero?
            @tokens[0].insert(0, Token::PSK)
          else
            @tokens[index - 1] << Token::PSK
          end
          @psk_count += 1
        elsif modifier == 'fallback'
          raise NotImplementedError
        else
          raise Noise::Exceptions::PSKValueError
        end
      end
    end

    # initiator [Boolean]
    def required_keypairs(initiator)
      initiator ? required_keypairs_of_initiator : required_keypairs_of_responder
    end

    def required_keypairs_of_initiator
      required = []
      required << :s if %w[K X I].include?(@name[0])
      required << :rs if one_way? || @name[1] == 'K'
      required
    end

    def required_keypairs_of_responder
      required = []
      required << :rs if @name[0] == 'K'
      required << :s if one_way? || %w[K X].include?(@name[1])
      required
    end

    def initiator_pre_messages
      @pre_messages[0].dup
    end

    def responder_pre_messages
      @pre_messages[1].dup
    end

    def one_way?
      false
    end
  end

  class OneWayPattern < Pattern
    def initialize(modifiers)
      super(modifiers)
    end

    def one_way?
      true
    end
  end

  class PatternN < OneWayPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'N'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES]]
    end
  end

  class PatternK < OneWayPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'K'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::SS]]
    end
  end

  class PatternX < OneWayPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'X'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::S, Token::SS]]
    end
  end

  class PatternNN < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'NN'
      @pre_messages = []
      @tokens = [[Token::E], [Token::E, Token::EE]]
    end
  end

  class PatternKN < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'KN'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternNK < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'NK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE]]
    end
  end

  class PatternKK < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'KK'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::SS], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternNX < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'NX'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES]]
    end
  end

  class PatternKX < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'KX'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE, Token::S, Token::ES]]
    end
  end

  class PatternXN < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'XN'
      @tokens = [[Token::E], [Token::E, Token::EE], [Token::S, Token::SE]]
    end
  end

  class PatternIN < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'IN'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternXK < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'XK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE], [Token::S, Token::SE]]
    end
  end

  class PatternIK < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'IK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::S, Token::SS], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternXX < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'XX'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES], [Token::S, Token::SE]]
    end
  end

  class PatternIX < Pattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'IX'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE, Token::S, Token::ES]]
    end
  end

  class DeferredPattern < Pattern
  end

  class PatternNK1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'NK1'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::ES]]
    end
  end

  class PatternNX1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'NX1'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S], [Token::ES]]
    end
  end

  class PatternX1N < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'X1N'
      @tokens = [[Token::E], [Token::E, Token::EE], [Token::S], [Token::SE]]
    end
  end

  class PatternX1K < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'X1K'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE], [Token::S], [Token::SE]]
    end
  end

  class PatternXK1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'XK1'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::ES], [Token::S, Token::SE]]
    end
  end

  class PatternX1K1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'X1K1'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::ES], [Token::S], [Token::SE]]
    end
  end

  class PatternX1X < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'X1X'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES], [Token::S], [Token::SE]]
    end
  end

  class PatternXX1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'XX1'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S], [Token::ES, Token::S, Token::SE]]
    end
  end

  class PatternX1X1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'X1X1'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S], [Token::ES, Token::S], [Token::SE]]
    end
  end

  class PatternK1N < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'K1N'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE], [Token::SE]]
    end
  end

  class PatternK1K < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'K1K'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE], [Token::SE]]
    end
  end

  class PatternKK1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'KK1'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE, Token::ES]]
    end
  end

  class PatternK1K1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'K1K1'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::ES], [Token::SE]]
    end
  end

  class PatternK1X < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'K1X'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES], [Token::SE]]
    end
  end

  class PatternKX1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'KX1'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE, Token::S], [Token::ES]]
    end
  end

  class PatternK1X1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'K1X1'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S], [Token::SE, Token::ES]]
    end
  end

  class PatternI1N < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'I1N'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE], [Token::SE]]
    end
  end

  class PatternI1K < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'I1K'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::S], [Token::E, Token::EE], [Token::SE]]
    end
  end

  class PatternIK1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'IK1'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE, Token::ES]]
    end
  end

  class PatternI1K1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'I1K1'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::ES], [Token::SE]]
    end
  end

  class PatternI1X < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'I1X'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::S, Token::ES], [Token::SE]]
    end
  end

  class PatternIX1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'IX1'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE, Token::S], [Token::ES]]
    end
  end

  class PatternI1X1 < DeferredPattern
    def initialize(modifiers)
      super(modifiers)
      @name = 'I1X1'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::S], [Token::SE, Token::ES]]
    end
  end
end
